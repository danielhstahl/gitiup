//! Git plumbing, one helper per fact the host needs from a repository.
//!
//! Everything here is a thin, testable wrapper over a git subcommand: it builds
//! objects (blobs, trees, commits), reads the ref advertisement, moves refs with
//! leases and turns objects into packfiles. Nothing here knows about gitiup's
//! error taxonomy beyond what [`GitFailure`] already maps — the host in
//! [`super`] is what turns these into refs and records.
//!
//! The commands are the *low-level* ones (`hash-object`, `mktree`, `commit-tree`,
//! `ls-tree`, `cat-file`, `ls-remote`, `fetch`, `push`, `pack-objects`,
//! `index-pack`), which is what lets the host drive a bare repository — or a
//! remote it can only reach over ssh or HTTP — without ever checking a working
//! tree out.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::run::{GitCli, GitFailure};
use crate::error::{HostError, HostResult};
use crate::refs::Actor;
use crate::time::Timestamp;

/// One `<oid>\t<refname>` line, as `git ls-remote` and `for-each-ref` print them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefLine {
    /// The object id, as git spelled it (40 hex for a sha1 repository).
    pub oid: String,
    /// The ref name, fully qualified (`refs/heads/main`).
    pub name: String,
    /// The object type, when the source reported one (`commit`, `tag`, `blob`).
    pub kind: Option<String>,
}

/// A record stored in the record store: one file in a chain commit's tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// The path inside the tree.
    pub path: String,
    /// The git blob id holding the bytes.
    pub blob: String,
    /// Size in bytes.
    pub size: u64,
}

/// A tree entry in `git mktree` form.
#[derive(Debug, Clone, Copy)]
pub struct TreeSpec<'a> {
    /// Mode, `100644` for a plain file.
    pub mode: &'a str,
    /// Object type, `blob` or `tree`.
    pub kind: &'a str,
    /// Object id.
    pub oid: &'a str,
    /// Path.
    pub path: &'a str,
}

/// The mode a record blob is stored with: plain files, never executables.
///
/// Records are data. Storing them 100644 also means a client that checks a
/// working tree out can never end up running one.
pub const RECORD_MODE: &str = "100644";

/// Write `bytes` as a blob object and return its git id.
pub fn write_blob(cli: &GitCli, bytes: &[u8]) -> HostResult<String> {
    cli.must_run(&["hash-object", "-w", "-t", "blob", "--stdin"], Some(bytes))
}

/// Build a tree from `entries`.
///
/// `git mktree` sorts the entries the way git stores them, so callers may hand
/// them over in any order.
pub fn make_tree(cli: &GitCli, entries: &[TreeSpec<'_>]) -> HostResult<String> {
    let mut input = String::new();
    for entry in entries {
        input.push_str(&format!(
            "{} {} {}\t{}\n",
            entry.mode, entry.kind, entry.oid, entry.path
        ));
    }
    if entries.is_empty() {
        // The empty tree, which git has exactly one of.
        return cli.must_run(&["mktree", "--missing"], None);
    }
    cli.must_run(&["mktree"], Some(input.as_bytes()))
}

/// The identity git should attribute a plumbing commit to.
///
/// gitiup writes commits nobody edits (ref pointers, record appends), and they
/// must say *who asked for them* rather than whoever's `user.name` happens to be
/// configured. `actor` becomes the author, and so the audit trail a reviewer
/// reads with `git log refs/attestations/<oid>`.
pub fn actor_identity(actor: Option<&Actor>) -> (String, String) {
    let name = actor.map(|a| a.as_str().to_string()).unwrap_or_else(|| {
        let unknown = Actor::unknown();
        unknown.as_str().to_string()
    });
    let display: String = name.chars().take(64).filter(|c| !c.is_control()).collect();
    let display = display.trim().to_string();
    let display = if display.is_empty() {
        "gitiup".to_string()
    } else {
        display
    };
    let email = if display.contains('@') {
        display.clone()
    } else {
        let slug: String = display
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        let slug = slug.trim_matches('-').to_string();
        let slug = if slug.is_empty() {
            "gitiup".to_string()
        } else {
            slug
        };
        format!("{slug}@gitiup.invalid")
    };
    (display, email)
}

/// Write a commit whose tree is `tree`, dated `when` and authored by `actor`.
pub fn commit_tree(
    cli: &GitCli,
    tree: &str,
    parents: &[String],
    message: &str,
    actor: Option<&Actor>,
    when: Timestamp,
) -> HostResult<String> {
    let (name, email) = actor_identity(actor);
    let mut args: Vec<String> = vec!["commit-tree".to_string(), tree.to_string()];
    for parent in parents {
        args.push("-p".to_string());
        args.push(parent.clone());
    }
    // The message goes over stdin, not argv: a caller-supplied message must not
    // be able to look like an option to git.
    args.push("-F".to_string());
    args.push("-".to_string());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let message = if message.trim().is_empty() {
        "gitiup ref update".to_string()
    } else {
        message.to_string()
    };
    let cli = cli
        .clone()
        .with_env("GIT_AUTHOR_NAME", &name)
        .with_env("GIT_AUTHOR_EMAIL", &email)
        .with_env("GIT_COMMITTER_NAME", &name)
        .with_env("GIT_COMMITTER_EMAIL", &email)
        .with_env("GIT_AUTHOR_DATE", format!("{} +0000", when.as_unix()))
        .with_env("GIT_COMMITTER_DATE", format!("{} +0000", when.as_unix()));
    cli.must_run(&args, Some(message.as_bytes()))
}

/// A single commit object as `for-each-ref`/`cat-file` expose it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    /// The commit id.
    pub oid: String,
    /// The root tree id.
    pub tree: String,
    /// Parents, newest first.
    pub parents: Vec<String>,
    /// Author/committer name.
    pub author: String,
    /// Committer unix time.
    pub commit_time: Option<u64>,
}

/// Read a commit object.
pub fn read_commit(cli: &GitCli, oid: &str) -> HostResult<Option<CommitInfo>> {
    let printed = match cli.run(&["cat-file", "-p", oid], None) {
        Ok(out) => out.stdout_text(),
        Err(failure) if failure.is_not_found() => return Ok(None),
        Err(failure) => return Err(failure.into()),
    };
    let mut info = CommitInfo {
        oid: oid.to_string(),
        tree: String::new(),
        parents: Vec::new(),
        author: String::new(),
        commit_time: None,
    };
    for line in printed.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("tree ") {
            info.tree = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("parent ") {
            info.parents.push(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("committer ") {
            let rest = rest.trim();
            if let Some((name, rest)) = rest.split_once('<') {
                info.author = name.trim().to_string();
                if let Some((_, stamp)) = rest.split_once('>')
                    && let Some(seconds) = stamp.trim().split(' ').next()
                {
                    info.commit_time = seconds.parse().ok();
                }
            }
        }
    }
    Ok(Some(info))
}

/// Read a blob by git rev syntax (`<commit>:<path>`, `<blob>`).
///
/// `Ok(None)` means "git says that is not there", which is a different answer
/// from "git could not run".
pub fn cat_blob(cli: &GitCli, rev: &str) -> HostResult<Option<Vec<u8>>> {
    match cli.run(&["cat-file", "blob", rev], None) {
        Ok(out) => Ok(Some(out.stdout)),
        Err(failure) if failure.is_not_found() => Ok(None),
        Err(failure) => Err(failure.into()),
    }
}

/// Read many blobs in one `cat-file --batch` process.
///
/// A ref listing may need a pointer document per ref, and one process per ref is
/// the difference between a listing that costs milliseconds and one that costs a
/// second.
pub fn cat_batch(cli: &GitCli, revs: &[String]) -> HostResult<Vec<Option<Vec<u8>>>> {
    if revs.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = String::new();
    for rev in revs {
        input.push_str(rev);
        input.push('\n');
    }
    let out = cli.run(&["cat-file", "--batch"], Some(input.as_bytes()))?;
    Ok(parse_batch(&out.stdout, revs.len()))
}

/// Parse `git cat-file --batch` output: `<oid> <type> <size>\n<size bytes>\n`, or
/// `missing\n` for a rev that is not there.
fn parse_batch(bytes: &[u8], expected: usize) -> Vec<Option<Vec<u8>>> {
    let mut out: Vec<Option<Vec<u8>>> = Vec::with_capacity(expected);
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let Some(nl) = find(bytes, cursor, b'\n') else {
            break;
        };
        let header = String::from_utf8_lossy(&bytes[cursor..nl]).to_string();
        cursor = nl + 1;
        if header == "missing" {
            out.push(None);
            continue;
        }
        let size: usize = match header.split(' ').next_back().and_then(|s| s.parse().ok()) {
            Some(size) => size,
            None => {
                out.push(None);
                continue;
            }
        };
        let end = cursor + size;
        if end > bytes.len() {
            out.push(None);
            break;
        }
        out.push(Some(bytes[cursor..end].to_vec()));
        // Skip the newline that terminates the payload.
        cursor = end + 1;
    }
    while out.len() < expected {
        out.push(None);
    }
    out.truncate(expected);
    out
}

fn find(haystack: &[u8], from: usize, needle: u8) -> Option<usize> {
    haystack[from..]
        .iter()
        .position(|b| *b == needle)
        .map(|at| at + from)
}

/// List a tree recursively (`git ls-tree -l -r <rev>`).
pub fn list_tree(cli: &GitCli, rev: &str) -> HostResult<Vec<TreeEntry>> {
    let text = match cli.run(&["ls-tree", "-l", "-r", rev], None) {
        Ok(out) => out.stdout_text(),
        Err(failure) if failure.is_not_found() => return Ok(Vec::new()),
        Err(failure) => return Err(failure.into()),
    };
    Ok(parse_ls_tree(&text))
}

/// `100644 blob <oid> <size>\t<path>` per line; `-l` adds the size column.
fn parse_ls_tree(text: &str) -> Vec<TreeEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((meta, path)) = line.split_once('\t') else {
            continue;
        };
        // `git ls-tree -l` right-aligns the size column, so the metadata is
        // whitespace-separated, not single-space-separated.
        let mut fields = meta.split_whitespace();
        let (Some(_mode), Some(kind), Some(oid)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if kind != "blob" {
            continue;
        }
        let size = fields
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        out.push(TreeEntry {
            path: path.to_string(),
            blob: oid.to_string(),
            size,
        });
    }
    out
}

/// Parse `git ls-remote` / `for-each-ref` output.
///
/// `ls-remote` prints `<oid>\t<refname>`, and `for-each-ref` with our format
/// string prints `<oid>\t<type>\t<refname>`; both are accepted here so callers do
/// not have to remember which they asked for.
pub fn parse_ref_lines(text: &str) -> Vec<RefLine> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let (Some(oid), Some(rest)) = (fields.next(), fields.next()) else {
            continue;
        };
        let (name, kind) = match fields.next() {
            // `for-each-ref` puts the type in the middle; `ls-remote` leaves the
            // second field as the name and has no third.
            Some(extra) => (extra.to_string(), Some(rest.to_string())),
            None => (rest.to_string(), None),
        };
        out.push(RefLine {
            oid: oid.to_string(),
            name,
            kind,
        });
    }
    out
}

/// The ref advertisement of a remote, optionally narrowed to `paths`.
pub fn ls_remote(cli: &GitCli, url: &str, paths: &[&str]) -> HostResult<Vec<RefLine>> {
    // The repository comes first: git reads the first non-option argument as the
    // remote, so a pattern placed before the URL is taken for the remote instead.
    let mut args: Vec<&str> = vec!["ls-remote", "--quiet", url];
    args.extend(paths.iter().copied());
    Ok(parse_ref_lines(&cli.must_run(&args, None)?))
}

/// The object one ref currently holds on `url`, freshly read.
///
/// CAS depends on this being a *fresh* read: a lease built from a stale
/// advertisement is not a lease, it is a guess.
pub fn ls_one(cli: &GitCli, url: &str, name: &str) -> HostResult<Option<String>> {
    let lines = ls_remote(cli, url, &[name])?;
    Ok(lines
        .into_iter()
        .find(|line| line.name == name)
        .map(|line| line.oid))
}

/// Refs held by the local mirror, sorted by name.
pub fn local_refs(cli: &GitCli) -> HostResult<Vec<RefLine>> {
    let mut lines = parse_ref_lines(&cli.must_run(
        &[
            "for-each-ref",
            "--format=%(objectname)\t%(objecttype)\t%(refname)",
        ],
        None,
    )?);
    lines.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(lines)
}

/// Copy every ref from `url` into the mirror, pruning refs the remote dropped.
///
/// This is `git fetch --prune --force <url> +refs/*:refs/*` — what `--mirror`
/// means, written out so it is obvious that gitiup fetches *everything*, including
/// the `refs/changes/**` and `refs/attestations/**` namespaces a normal clone
/// would leave out.
pub fn fetch_all(cli: &GitCli, url: &str) -> HostResult<()> {
    cli.must_run(
        &[
            "fetch",
            "--prune",
            "--force",
            "--quiet",
            "--no-tags",
            url,
            "+refs/*:refs/*",
        ],
        None,
    )?;
    Ok(())
}

/// Fetch one object (and its history) from `url` into the mirror.
///
/// Servers only hand out an arbitrary object id when they are configured to, so
/// this is best-effort: the caller decides what a miss means.
pub fn fetch_object(cli: &GitCli, url: &str, oid: &str) -> HostResult<()> {
    cli.must_run(
        &["fetch", "--force", "--quiet", "--no-tags", url, oid],
        None,
    )?;
    Ok(())
}

/// One ref move: `<src>:<dst>`, with the empty src git reads as a deletion.
#[derive(Debug, Clone)]
pub struct Push {
    /// Object to point the ref at; `None` deletes it.
    pub src: Option<String>,
    /// Ref to move.
    pub dst: String,
    /// The lease for this ref, `Some(expected)` — a zero oid means "must not
    /// exist", which is how `Expect::Absent` is emulated.
    pub lease: Option<String>,
}

impl Push {
    /// The `git push` refspec for this move.
    pub fn refspec(&self) -> String {
        match &self.src {
            Some(src) => format!("{src}:{}", self.dst),
            None => format!(":{}", self.dst),
        }
    }
}

/// How to ask the remote for a push.
#[derive(Debug, Clone, Copy, Default)]
pub struct PushStyle {
    /// Send `--atomic`, so a batch is one transaction on the receiving side.
    pub atomic: bool,
    /// `--dry-run`: ask the remote to accept the ref line without moving it.
    pub dry_run: bool,
    /// Append `--force` (only for an unconditional write, which has no lease).
    pub force: bool,
}

/// Build the argv for a push. Kept separate so a test can assert the flags —
/// `--force` and a named lease are mutually exclusive, and passing both silently
/// turns off compare-and-swap.
pub fn push_args(url: &str, pushes: &[Push], style: PushStyle) -> Vec<String> {
    let mut args: Vec<String> = vec!["push".to_string()];
    if style.dry_run {
        args.push("--dry-run".to_string());
    }
    if style.atomic {
        args.push("--atomic".to_string());
    }
    let mut leased = false;
    for push in pushes {
        if let Some(expect) = &push.lease {
            leased = true;
            args.push(format!("--force-with-lease={}:{expect}", push.dst));
        }
    }
    if style.force && !leased {
        args.push("--force".to_string());
    }
    args.push(url.to_string());
    for push in pushes {
        args.push(push.refspec());
    }
    args
}

/// Move refs on a remote.
///
/// `Err(GitFailure)` carries git's own words: `is_stale_lease()` says "somebody
/// else moved the ref first" and every other classification belongs to
/// [`super::run`].
pub fn push(cli: &GitCli, url: &str, pushes: &[Push], style: PushStyle) -> Result<(), GitFailure> {
    let args = push_args(url, pushes, style);
    let owned: Vec<&str> = args.iter().map(String::as_str).collect();
    match cli.run(&owned, None) {
        Ok(_) => Ok(()),
        Err(failure) => Err(failure),
    }
}

/// The bytes of a packfile carrying `wants` and skipping `haves`.
///
/// `git rev-list --objects <wants> --not <haves> | git pack-objects --stdout` is
/// exactly what a server does for a `git fetch`, and it is why an attestation
/// published onto a ref is *fetched*, not downloaded: a client that already has
/// the commit asks for nothing.
pub fn pack_objects(cli: &GitCli, wants: &[String], haves: &[String]) -> HostResult<Vec<u8>> {
    if wants.is_empty() {
        return Ok(Vec::new());
    }
    let mut args: Vec<String> = vec!["rev-list".to_string(), "--objects".to_string()];
    args.extend(wants.iter().cloned());
    if !haves.is_empty() {
        args.push("--not".to_string());
        args.extend(haves.iter().cloned());
    }
    let owned: Vec<&str> = args.iter().map(String::as_str).collect();
    let objects = cli.run(&owned, None)?.stdout_text();
    if objects.trim().is_empty() {
        return Ok(Vec::new());
    }
    let pack = cli.run(
        &[
            "pack-objects",
            "--stdout",
            "--delta-base-offset",
            "--non-empty",
        ],
        Some(objects.as_bytes()),
    )?;
    Ok(pack.stdout)
}

/// Ingest a packfile into the mirror's object database.
pub fn index_pack(cli: &GitCli, bytes: &[u8]) -> HostResult<String> {
    let out = cli.run(&["index-pack", "--stdin", "--fix-thin"], Some(bytes))?;
    Ok(out.trimmed())
}

/// When each path in a linear chain of commits was introduced.
///
/// `git log --format=@<time> --name-only <rev>` walks newest-first, so the first
/// time a path appears is the commit that added it — which is the record store's
/// `created_at` without a `git log` per record.
pub fn introduced_at(cli: &GitCli, rev: &str) -> HostResult<BTreeMap<String, u64>> {
    let text = match cli.run(&["log", "--format=@%ct", "--name-only", rev], None) {
        Ok(out) => out.stdout_text(),
        Err(failure) if failure.is_not_found() => return Ok(BTreeMap::new()),
        Err(failure) => return Err(failure.into()),
    };
    let mut out = BTreeMap::new();
    let mut current: Option<u64> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(stamp) = line.strip_prefix('@') {
            current = stamp.parse().ok();
            continue;
        }
        if let Some(at) = current {
            out.entry(line.to_string()).or_insert(at);
        }
    }
    Ok(out)
}

/// The document stored inside a pointer commit: what the ref's *gitiup* value is,
/// who wrote it and when.
///
/// A git ref can only hold a git object id, but a gitiup ref often points at a
/// record (an attestation, a change) whose digest is SHA-256 of the record bytes
/// — a value git cannot store. The pointer commit is the bridge: the ref holds a
/// commit, the commit holds this document plus the record itself, so `git fetch`
/// carries the proof and `gitiup` recovers the digest it promised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefDocument {
    /// Schema of this document (see [`crate::HOST_SCHEMA_VERSION`]).
    pub schema: u32,
    /// Marker so a reader can tell a gitiup pointer from an ordinary commit.
    pub kind: String,
    /// The gitiup value: hex of a record digest, or a git object id.
    pub oid: String,
    /// Who wrote it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Actor>,
    /// When it was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Timestamp>,
    /// The message that came with the update, for audit trails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Name of the ref document inside a pointer commit's tree.
pub const REF_DOC_PATH: &str = "gitiup-ref.json";

/// Name of the record bytes inside a pointer commit's tree.
pub const RECORD_PATH: &str = "record";

impl RefDocument {
    /// A document for `oid`.
    pub fn new(oid: &str) -> RefDocument {
        RefDocument {
            schema: crate::HOST_SCHEMA_VERSION,
            kind: "gitiup-ref".to_string(),
            oid: oid.to_string(),
            updated_by: None,
            updated_at: None,
            message: None,
        }
    }

    /// The canonical JSON bytes (so two hosts agree on one document's bytes).
    pub fn encode(&self) -> HostResult<Vec<u8>> {
        crate::config::canonical_json(self)
    }

    /// Parse a stored document, refusing a newer schema.
    pub fn decode(bytes: &[u8]) -> HostResult<RefDocument> {
        let doc: RefDocument = serde_json::from_slice(bytes).map_err(|e| {
            HostError::invalid("gitiup-ref.json", format!("cannot parse ref document: {e}"))
        })?;
        if doc.schema > crate::HOST_SCHEMA_VERSION_MAX {
            return Err(HostError::invalid(
                "gitiup-ref.json",
                format!(
                    "ref document is schema {}, and this build reads up to {}",
                    doc.schema,
                    crate::HOST_SCHEMA_VERSION_MAX
                ),
            )
            .with_hint("upgrade gitiup to read this ref"));
        }
        Ok(doc)
    }
}

/// A store manifest: what a gitiup store claims to be, written once per store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostManifest {
    /// Schema version.
    pub schema: u32,
    /// Which host implementation, `git`.
    pub kind: String,
    /// The remote URL, redacted.
    pub url: String,
    /// Store prefix as configured (recorded, not used for the ref layout).
    pub store_prefix: String,
    /// When the store was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
    /// Who created it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Implementation string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implemented_by: Option<String>,
}

impl HostManifest {
    /// The `host.json` bytes.
    pub fn encode(&self) -> HostResult<Vec<u8>> {
        crate::config::canonical_json(self)
    }

    /// Parse `host.json`.
    pub fn decode(bytes: &[u8]) -> HostResult<HostManifest> {
        serde_json::from_slice(bytes).map_err(|e| {
            HostError::invalid("host.json", format!("cannot parse store manifest: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_line_parsing_handles_both_formats() {
        let ls = "abc\trefs/heads/main\n";
        let lines = parse_ref_lines(ls);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].name, "refs/heads/main");
        assert_eq!(lines[0].kind, None);

        let each = "abc\tcommit\trefs/heads/main\n";
        let lines = parse_ref_lines(each);
        assert_eq!(lines[0].name, "refs/heads/main");
        assert_eq!(lines[0].kind.as_deref(), Some("commit"));
        assert!(parse_ref_lines("").is_empty());
        assert!(parse_ref_lines("garbage").is_empty());
    }

    #[test]
    fn tree_listings_parse_the_size_column() {
        let text = "100644 blob 1111111111111111111111111111111111111111 12\tdeadbeef\n\
                    040000 tree 2222222222222222222222222222222222222222\tsub\n";
        let entries = parse_ls_tree(text);
        assert_eq!(entries.len(), 1, "trees are not records");
        assert_eq!(entries[0].path, "deadbeef");
        assert_eq!(entries[0].size, 12);
    }

    #[test]
    fn batch_output_includes_missing_objects() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"aaaa blob 5\nhello\n");
        bytes.extend_from_slice(b"missing\n");
        bytes.extend_from_slice(b"bbbb blob 0\n\n");
        let parsed = parse_batch(&bytes, 4);
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].as_deref(), Some(&b"hello"[..]));
        assert_eq!(parsed[1], None);
        assert_eq!(parsed[2].as_deref(), Some(&b""[..]));
        assert_eq!(
            parsed[3], None,
            "a short response pads with None, not a hang"
        );
    }

    #[test]
    fn push_argv_keeps_force_and_lease_apart() {
        let pushes = vec![
            Push {
                src: Some("aaa".into()),
                dst: "refs/heads/a".into(),
                lease: Some("0".repeat(40)),
            },
            Push {
                src: None,
                dst: "refs/heads/b".into(),
                lease: Some("bbb".into()),
            },
        ];
        let args = push_args(
            "url",
            &pushes,
            PushStyle {
                atomic: true,
                dry_run: true,
                force: true,
            },
        );
        let text = args.join(" ");
        assert!(text.contains("--atomic"), "{text}");
        assert!(text.contains("--dry-run"), "{text}");
        assert!(text.contains("--force-with-lease=refs/heads/a:"), "{text}");
        assert!(
            !text.contains(" --force "),
            "--force disables the lease: {text}"
        );
        assert_eq!(pushes[1].refspec(), ":refs/heads/b");

        // An unconditional write has no lease, so it needs --force.
        let plain = vec![Push {
            src: Some("aaa".into()),
            dst: "refs/heads/a".into(),
            lease: None,
        }];
        let args = push_args(
            "url",
            &plain,
            PushStyle {
                force: true,
                ..Default::default()
            },
        );
        assert!(args.join(" ").contains(" --force "), "{args:?}");
    }

    #[test]
    fn actors_become_git_identities() {
        let (name, email) = actor_identity(Some(&Actor::new("Ada L").unwrap()));
        assert_eq!(name, "Ada L");
        assert_eq!(email, "ada-l@gitiup.invalid");
        let (name, email) = actor_identity(Some(&Actor::new("ada@example.com").unwrap()));
        assert_eq!(name, "ada@example.com");
        assert_eq!(email, "ada@example.com");
        let (name, _) = actor_identity(None);
        assert_eq!(name, "unknown");
    }

    #[test]
    fn ref_documents_round_trip_and_refuse_newer_schemas() {
        let mut doc = RefDocument::new("aabb");
        doc.updated_by = Some(Actor::new("ada").unwrap());
        doc.message = Some("open c1".into());
        let bytes = doc.encode().unwrap();
        assert_eq!(RefDocument::decode(&bytes).unwrap(), doc);
        let future = br#"{"schema":99,"kind":"gitiup-ref","oid":"aabb"}"#;
        let err = RefDocument::decode(future).unwrap_err();
        assert_eq!(err.kind(), crate::HostErrorKind::Invalid);
        assert!(err.hint().unwrap().contains("upgrade"), "{err}");
    }
}

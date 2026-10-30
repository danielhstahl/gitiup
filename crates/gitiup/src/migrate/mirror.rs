//! The git side of a repository migration: a bare mirror of the forge's git endpoint,
//! and the object plumbing that moves its bytes into another store.
//!
//! History does not travel through a forge API. There is no endpoint that hands out a
//! packfile and none that takes one, and [ADR-0005's](../../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)
//! own copy step says the same thing about code: it moves over a pack path or it does not
//! move. So this command does the one thing that works — `git fetch` from the forge's clone
//! URL into a **local bare mirror**, then hand those objects to the destination through the
//! destination's own pack path — and the mirror is where the ticket's "resume from where it
//! stopped" comes almost free: a `git fetch` that dies at 38 GB of 40 GB has already put
//! 38 GB of objects in the mirror's object database, and the next fetch asks for the
//! remainder.
//!
//! Two destinations, two object paths, and the difference is reported rather than hidden:
//!
//! | destination | what arrives | what a reader can do with it |
//!|------------|--------------|------------------------------|
//!| a git repository (the plain-git host) | a git packfile, `index-pack`ed | `git log`, `git fetch`, and a re-read of any commit by name |
//!| a bucket or a directory store | each object as a gitiup record | gitiup can return the bytes of any object it was given; `git fetch` cannot carry them |
//!
//! The second row is not a failure and it is not the first row either, which is why
//! [`ObjectForm`] carries the distinction into the report: a bucket has no git object
//! database, and a tool that pretended otherwise would have a store whose refs name
//! commits nothing can read.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use gitiup_host::hosts::git::run::GitCli;
use gitiup_host::{HostError, HostResult};

/// How many objects one batch of loose records carries.
///
/// A bucket destination takes object *contents*, and reading a whole repository's worth
/// into memory at once is how a migration of a big repository becomes an OOM instead of a
/// copy. Batching bounds the memory; it does not change what arrives, because every record
/// is create-only and a repeat is `already`.
pub const BATCH_OBJECTS: usize = 2000;

/// The refspecs this mirror fetches: branches and tags, nothing else.
///
/// `+refs/*:refs/*` would also take the forge's own plumbing (`refs/pull/**`, which is
/// where GitHub puts a pull request's head), and the pull-request heads this migration
/// needs it for are already named by the pull records it reads. Fetching the plumbing too
/// would move bytes the destination has no namespace for.
pub const REFSPECS: &[&str] = &["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"];

/// A bare mirror of one git endpoint, kept between runs.
pub struct Mirror {
    cli: GitCli,
    path: PathBuf,
    url: String,
}

impl Mirror {
    /// Open (creating if needed) a bare mirror of `url` at `path`.
    pub fn open(path: &Path, url: &str) -> HostResult<Mirror> {
        let program = gitiup_host::hosts::git::git_program().ok_or_else(|| {
            HostError::unsupported(
                "git-binary",
                "moving history needs the `git` binary and none was found on PATH",
            )
            .with_hint(
                "install git, or pass --no-history to migrate the refs, changes and \
                 proofs alone",
            )
        })?;
        if !path.join("objects").is_dir() {
            gitiup_host::hosts::git::init_bare(path)?;
        }
        let cli = GitCli::discover(&program)?.with_git_dir(path);
        Ok(Mirror {
            cli,
            path: path.to_path_buf(),
            url: url.to_string(),
        })
    }

    /// Fetch branches and tags.
    ///
    /// `--progress` goes to *this* process's stderr rather than being captured: the ticket's
    /// scenario is a 40 GB clone over a bad link, and a command that goes silent for an hour
    /// while it does one is a command that gets interrupted, which is the failure the mirror
    /// exists to survive.
    pub fn fetch(&self) -> HostResult<()> {
        let mut command = Command::new(self.cli.program());
        command
            .current_dir(&self.path)
            .arg("fetch")
            .args(["--prune", "--force", "--progress"])
            .arg(&self.url)
            .args(REFSPECS)
            .stdin(Stdio::null())
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ADVICE", "0");
        let status = command
            .status()
            .map_err(|e| HostError::from_io("run git fetch", &self.path, e))?;
        if !status.success() {
            return Err(HostError::unreachable(format!(
                "`git fetch` from {} exited with {}",
                self.url,
                status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "a signal".to_string())
            ))
            .with_hint(
                "the mirror keeps whatever it did fetch: run the same command again and it \
                 asks for the rest",
            ));
        }
        Ok(())
    }

    /// The local refs the mirror holds, as `(name, oid)`.
    pub fn refs(&self) -> HostResult<Vec<(String, String)>> {
        let text = self.cli.must_run(
            &[
                "for-each-ref",
                "--format=%(objectname) %(refname)",
                "refs/heads",
                "refs/tags",
            ],
            None,
        )?;
        Ok(text
            .lines()
            .filter_map(|line| {
                let (oid, name) = line.split_once(' ')?;
                Some((name.to_string(), oid.to_string()))
            })
            .collect())
    }

    /// Whether the mirror holds this object.
    pub fn holds(&self, oid: &str) -> bool {
        self.cli.has_object(oid)
    }

    /// The objects reachable from `wants` and not from `not`, as oids.
    ///
    /// This is the whole of the "what does the destination not have yet" question: the
    /// `not` set is the tips already delivered by earlier units of this run (or an earlier
    /// run, from the journal), so each ref contributes its own history and nothing twice.
    /// It can over-deliver when two refs share no history; it cannot under-deliver, and a
    /// record stored twice is the same record.
    pub fn objects(&self, wants: &[String], not: &[String]) -> HostResult<Vec<String>> {
        if wants.is_empty() {
            return Ok(Vec::new());
        }
        let mut args: Vec<String> = vec!["rev-list".into(), "--objects".into()];
        args.extend(wants.iter().cloned());
        if !not.is_empty() {
            args.push("--not".into());
            args.extend(not.iter().cloned());
        }
        let owned: Vec<&str> = args.iter().map(String::as_str).collect();
        // `rev-list --objects` prints `oid path` for a blob or tree and a bare oid for a
        // commit; the path is the diff hint and never part of the object's name.
        let text = match self.cli.run(&owned, None) {
            Ok(out) => out.stdout_text(),
            // A tip the mirror does not have (a PR head that was never reachable from a
            // branch, on a forge that GC'd it) is a missing object, not a broken mirror.
            Err(failure) if failure.is_not_found() => return Ok(Vec::new()),
            Err(failure) => return Err(failure.into()),
        };
        let mut seen: Vec<String> = Vec::new();
        for line in text.lines() {
            if let Some(oid) = line.split_whitespace().next()
                && oid.len() >= 40
                && !seen.iter().any(|held| held == oid)
            {
                seen.push(oid.to_string());
            }
        }
        Ok(seen)
    }

    /// The contents of `oids`, in that order.
    pub fn contents(&self, oids: &[String]) -> HostResult<Vec<Vec<u8>>> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        let input = format!("{}\n", oids.join("\n"));
        let out = self
            .cli
            .run(&["cat-file", "--batch"], Some(input.as_bytes()))?
            .stdout;
        parse_batch(&out).ok_or_else(|| {
            HostError::invalid(
                "git cat-file --batch",
                "the output ended in the middle of an object",
            )
        })
    }

    /// A git packfile carrying exactly `oids`.
    pub fn packfile(&self, oids: &[String]) -> HostResult<Vec<u8>> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        let list = oids.join("\n");
        Ok(self
            .cli
            .run(
                &["pack-objects", "--stdout", "--quiet", "--delta-base-offset"],
                Some(list.as_bytes()),
            )?
            .stdout)
    }

    /// Ingest a packfile into a scratch object database and report which of `wants` that
    /// database will name.
    ///
    /// `git index-pack` hashes every object as it indexes it and refuses a pack whose
    /// objects do not hash to the names they arrive under, so "the object is in the index"
    /// *is* the re-hash — which is the point of asking git to do it rather than trusting the
    /// bytes because our own process wrote them.
    pub fn index_and_check(
        pack: &[u8],
        wants: &[String],
        scratch: &Path,
    ) -> HostResult<Vec<String>> {
        if !scratch.join("objects").is_dir() {
            gitiup_host::hosts::git::init_bare(scratch)?;
        }
        let program = gitiup_host::hosts::git::git_program()
            .ok_or_else(|| HostError::unsupported("git-binary", "no git binary"))?;
        let cli = GitCli::discover(&program)?.with_git_dir(scratch);
        if !pack.is_empty() {
            gitiup_host::hosts::git::plumb::index_pack(&cli, pack)?;
        }
        Ok(wants
            .iter()
            .filter(|oid| cli.has_object(oid))
            .cloned()
            .collect())
    }
}

/// Re-hash commit contents the way git names a commit.
///
/// Standalone because the verification step runs whether or not a mirror was ever opened:
/// `--no-history` still has to answer "what did the proofs arrive about", and answering it
/// needs the arithmetic, not the clone. It runs `git` without a `--git-dir` on purpose:
/// `hash-object --stdin` names bytes, it does not store them, so it needs no repository to
/// do it in.
pub fn hash_commit(bytes: &[u8]) -> HostResult<String> {
    let program = gitiup_host::hosts::git::git_program().ok_or_else(|| {
        HostError::unsupported("git-binary", "re-hashing a commit needs the `git` binary")
    })?;
    let mut command = std::process::Command::new(&program);
    command
        .args(["hash-object", "-t", "commit", "--stdin"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ADVICE", "0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|e| HostError::invalid("git hash-object", format!("{e}")))?;
    {
        use std::io::Write;
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| HostError::invalid("git hash-object", "no stdin"))?;
        stdin
            .write_all(bytes)
            .map_err(|e| HostError::invalid("git hash-object", format!("{e}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| HostError::invalid("git hash-object", format!("{e}")))?;
    if !out.status.success() {
        return Err(HostError::invalid(
            "git hash-object",
            format!(
                "git named these bytes no commit name (exit {:?})",
                out.status.code()
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `git cat-file --batch` output, object by object, contents only.
fn parse_batch(out: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut objects = Vec::new();
    let mut index = 0usize;
    while index < out.len() {
        // `git cat-file --batch` frames each object as `<oid> <type> <size>\n<content>\n`.
        // The header is one line and the content is exactly `size` bytes after it, so a
        // commit whose message is full of newlines is read as one object and not as many.
        let end = out[index..].iter().position(|byte| *byte == b'\n')? + index;
        let header = String::from_utf8_lossy(&out[index..end]).to_string();
        index = end + 1;
        let fields: Vec<&str> = header.split_whitespace().collect();
        if fields.len() < 3 {
            return None;
        }
        let size: usize = fields[2].parse().ok()?;
        if index + size > out.len() {
            return None;
        }
        objects.push(out[index..index + size].to_vec());
        index += size + 1;
    }
    Some(objects)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_output_is_split_on_git_own_headers() {
        // Exactly the framing `git cat-file --batch` produces, byte for byte.
        let one = b"blob\n";
        let mut wire = format!("abc123 blob {}\n", one.len()).into_bytes();
        wire.extend_from_slice(one);
        wire.push(b'\n');
        let parsed = parse_batch(&wire).expect("one object");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], one.to_vec());
        // A commit: the content has newlines in it, and the size is what ends the object.
        let commit = b"tree abc\nauthor Ada <ada@example.org> 1 +0000\n\nchange\n";
        let mut two = format!("def456 commit {}\n", commit.len()).into_bytes();
        two.extend_from_slice(commit);
        two.push(b'\n');
        let parsed = parse_batch(&two).expect("a commit");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], commit.to_vec());
        // A header with no size is not an object, and guessing would silently drop bytes.
        assert!(parse_batch(b"abc123 blob\n").is_none());
        assert!(parse_batch(b"abc123 blob 9\nshort").is_none());
    }

    #[test]
    fn only_branches_and_tags_are_fetched() {
        for refspec in REFSPECS {
            assert!(
                refspec.starts_with("+refs/heads") || refspec.starts_with("+refs/tags"),
                "the mirror must not reach for a forge's own plumbing: {refspec}"
            );
        }
        assert!(!REFSPECS.iter().any(|spec| spec.contains("refs/*")));
    }
}

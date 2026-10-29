//! A change over the git transport, where the interesting claim lives: **one plain
//! `git fetch` carries the record *and* the commits it proposes** (ADR-0003 C1, D5), and
//! the ref's own commit history *is* the attempt history.
//!
//! Everything here is checked with the `git` binary on a fresh clone rather than through
//! gitiup's own reader, because the promise being tested is the one a stranger relies
//! on: they fetched a ref and got the whole proposal, with no second protocol and no
//! gitiup installed.

use std::path::{Path, PathBuf};
use std::process::Command;

use change_support::*;
use gitiup_host::change::{self, ChangeRef, State};
use gitiup_host::hosts::git::GitHost;
use gitiup_host::{
    Actor, BlobStore, HostErrorExt, Namespace, Oid, RefStore, RefUpdate, RemoteConfig,
};

mod change_support;

fn require_git() {
    if gitiup_host::hosts::git::git_program().is_none() {
        panic!("this test needs the git binary to mean anything");
    }
}

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `git cat-file` that tolerates a missing object, because "the pack did not carry it"
/// is the failure this file exists to catch and it should read as one.
fn try_git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn git_in(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A bare repository with two real commits on `refs/heads/main`, and a `GitHost` on it
/// with its own mirror.
struct Repo {
    dir: tempfile::TempDir,
    repo: PathBuf,
    /// The commits the two attempts propose, in order.
    commits: Vec<String>,
}

impl Repo {
    fn new() -> Repo {
        let dir = tempfile::tempdir().expect("temp dir");
        let repo = dir.path().join("repo.git");
        gitiup_host::hosts::git::init_bare(&repo).expect("init bare repository");

        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).expect("work dir");
        git_in(&work, &["init", "-q", "-b", "main"]);
        git_in(&work, &["config", "user.email", "ada@example.org"]);
        git_in(&work, &["config", "user.name", "Ada"]);
        let mut commits = Vec::new();
        for step in ["first", "second"] {
            std::fs::write(work.join(format!("{step}.txt")), format!("{step}\n")).expect("file");
            git_in(&work, &["add", "."]);
            git_in(&work, &["commit", "-q", "-m", &format!("{step} commit")]);
            commits.push(git_in(&work, &["rev-parse", "HEAD"]));
        }
        git_in(
            &work,
            &[
                "push",
                "--quiet",
                &format!("file://{}", repo.display()),
                "HEAD:refs/heads/main",
            ],
        );
        Repo { dir, repo, commits }
    }

    fn url(&self) -> String {
        format!("file://{}", self.repo.display())
    }

    fn host(&self, name: &str) -> GitHost {
        let remote = RemoteConfig::new(name, &self.url())
            .expect("file url")
            .with_option(
                "work-dir",
                self.dir
                    .path()
                    .join(format!("mirror-{name}"))
                    .display()
                    .to_string(),
            );
        GitHost::open_or_init(&remote).expect("open the git host")
    }
}

/// A record about real commits, signed by `who`: `anchor` is the commit attempt 0
/// started from, `head` the one this attempt proposes.
fn real_change(
    who: &str,
    title: &str,
    anchor: &str,
    head: &str,
    index: u32,
    previous: Option<String>,
) -> change::ChangeRecord {
    let mut record = change_record(who, title, &oid(anchor), &oid(head), index, previous);
    record.base.oid = oid(anchor);
    record.sign(&fixture_key(who)).expect("sign")
}

/// A git commit id in the record's own oid form.
fn oid(commit: &str) -> String {
    format!("sha1:{commit}")
}

#[test]
fn one_plain_fetch_carries_the_change_and_every_commit_it_proposes() {
    require_git();
    let scratch = Repo::new();
    let host = scratch.host("origin");
    let (first_commit, second_commit) = (&scratch.commits[0], &scratch.commits[1]);

    let first = real_change("ada", "A real change", first_commit, first_commit, 0, None);
    let published = change::publish_change(&host, &first, Actor::new("ada").unwrap())
        .expect("publish attempt 0");

    let second = real_change(
        "ada",
        "A real change",
        first_commit,
        second_commit,
        1,
        Some(first.change_digest().unwrap()),
    );
    let republished = change::publish_change(&host, &second, "ada").expect("attempt 1");
    assert_eq!(published.change_id, republished.change_id);

    // A change is the user's data, so it is advertised: `refs/changes/**` is never
    // hidden the way a host's own `refs/gitiup/**` bookkeeping is (D5).
    let advertised = git(&scratch.repo, &["for-each-ref", "--format=%(refname)"]);
    for name in [
        change::change_head_ref(&first.change_id).as_str(),
        change::attempt_ref(&first.change_id, 0).as_str(),
        change::attempt_ref(&first.change_id, 1).as_str(),
    ] {
        assert!(advertised.contains(name), "{name} is not advertised");
    }

    // Now the stranger: one fetch of the change's ref subtree, into a store that has
    // never seen this repository — no gitiup, no second protocol (C1).
    let fresh = scratch.dir.path().join("stranger.git");
    gitiup_host::hosts::git::init_bare(&fresh).expect("init the stranger");
    let pattern = change::fetch_pattern(&first.change_id);
    git(
        &fresh,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            &scratch.url(),
            &format!("{pattern}:{pattern}"),
        ],
    );

    // 1. Both proposed commits travelled, which is the whole point of parenting the
    //    pointer commit on them (D5's first requirement).
    for commit in [first_commit, second_commit] {
        assert!(
            try_git(
                &fresh,
                &["rev-parse", "--verify", &format!("{commit}^{{commit}}")]
            )
            .is_some(),
            "the fetch of {pattern} did not carry commit {commit}"
        );
    }

    // 2. The record bytes came too, verbatim, in the same packfile — and the pointer
    //    document beside them promises exactly the digest the record earns (D4, D5).
    for (reference, record) in [
        (change::attempt_ref(&first.change_id, 0), &first),
        (change::attempt_ref(&first.change_id, 1), &second),
        (change::change_head_ref(&first.change_id), &second),
    ] {
        let carried = try_git(
            &fresh,
            &["cat-file", "blob", &format!("{reference}:record")],
        )
        .unwrap_or_else(|| panic!("{reference} did not carry its record bytes"));
        assert_eq!(
            carried.as_bytes(),
            record.canonical_bytes().unwrap().as_slice(),
            "{reference} carried different bytes than the record's own canonical form"
        );
        let document: serde_json::Value = serde_json::from_str(
            &try_git(
                &fresh,
                &["cat-file", "blob", &format!("{reference}:gitiup-ref.json")],
            )
            .expect("the pointer document travels with the pointer commit"),
        )
        .expect("gitiup-ref.json parses");
        assert_eq!(
            document["oid"].as_str().unwrap(),
            record.digest().unwrap().hex(),
            "{reference} promises a different digest than the record it carries"
        );
    }

    // 3. The ref's own history *is* the attempt history: attempt 1's pointer commit is
    //    parented on attempt 0's, so one `git log` walks the force-push (D5, D6).
    let history = git(
        &fresh,
        &[
            "rev-list",
            change::attempt_ref(&first.change_id, 1).as_str(),
        ],
    );
    let attempt0_pointer = git(
        &fresh,
        &[
            "rev-parse",
            change::attempt_ref(&first.change_id, 0).as_str(),
        ],
    );
    assert!(
        history.lines().any(|line| line == attempt0_pointer),
        "attempt 1's history does not include attempt 0's pointer commit:\n{history}"
    );
    assert!(
        history.lines().any(|line| line == first_commit)
            && history.lines().any(|line| line == second_commit),
        "the attempt history should carry both proposed commits:\n{history}"
    );
    // And `git log refs/changes/<id>/head` says the same thing as the module's own
    // history reader, which is the agreement D6 promises.
    let head_log = git(
        &fresh,
        &[
            "rev-list",
            change::change_head_ref(&first.change_id).as_str(),
        ],
    );
    assert!(head_log.contains(&attempt0_pointer));
    assert_eq!(
        change::change_history(&host, &first.change_id)
            .unwrap()
            .iter()
            .map(|attempt| attempt.head.clone())
            .collect::<Vec<_>>(),
        vec![oid(first_commit), oid(second_commit)],
        "the store's history and git's log of the same ref must agree"
    );

    // 4. Another gitiup handle, with a mirror that never wrote anything, reads the same
    //    truth.
    let peer = scratch.host("peer");
    let head = change::change_at(&peer, &change::change_head_ref(&first.change_id)).unwrap();
    assert_eq!(head.digest, second.digest().unwrap());
    assert_eq!(
        head.target,
        ChangeRef::Head {
            id: first.change_id.clone()
        }
    );
    assert_eq!(
        change::list_changes(&peer).unwrap().changes[0].state,
        State::Open
    );
}

#[test]
fn a_change_ref_holds_a_digest_and_parents_the_commit_it_proposes() {
    require_git();
    let scratch = Repo::new();
    let host = scratch.host("origin");
    let commit = &scratch.commits[0];
    let record = real_change("ada", "The ref value is a digest", commit, commit, 0, None);
    change::publish_change(&host, &record, "ada").unwrap();

    let reference = change::change_head_ref(&record.change_id);
    // The gitiup value is the record digest, which git cannot spell: 32 bytes.
    let seen = host.get_ref(&reference).unwrap().unwrap();
    assert_eq!(seen.oid, record.digest().unwrap());
    assert_eq!(seen.oid.len(), 32, "a sha256 record digest");
    // What git holds is the pointer commit, and it is parented on the proposed commit.
    let pointer = git(&scratch.repo, &["rev-parse", reference.as_str()]);
    assert_eq!(
        git(&scratch.repo, &["cat-file", "-t", &pointer]),
        "commit",
        "what the ref holds is a commit; gitiup spells its value as a digest"
    );
    let parents = git(
        &scratch.repo,
        &["rev-list", "--parents", "-n", "1", reference.as_str()],
    );
    let fields: Vec<&str> = parents.split_whitespace().collect();
    assert!(
        fields.contains(&commit.as_str()),
        "the pointer commit must reach the commit it proposes: {parents}"
    );

    // The record is also addressable as a CAS object on this host (its own store), and
    // a ref write that would overwrite an attempt is refused by lease, as everywhere.
    assert_eq!(
        host.get(&record.digest().unwrap()).unwrap().as_deref(),
        Some(record.canonical_bytes().unwrap().as_slice())
    );
    assert_eq!(
        host.list(&Namespace::CHANGE)
            .unwrap()
            .iter()
            .filter(|entry| entry.oid == record.digest().unwrap())
            .count(),
        1
    );
    let attempt = change::attempt_ref(&record.change_id, 0);
    let err = host
        .update_ref_cas(&RefUpdate::create(attempt, Oid::hash_bytes(b"other")))
        .unwrap_err();
    assert!(err.is_conflict(), "attempt refs are create-only: {err}");
}

//! The HTTP transports: smart HTTP through `git-http-backend`, and dumb HTTP off
//! a static file server.
//!
//! These are the "host a repo on a static web server, no forge, no SSH daemon"
//! acceptance paths. Rather than depend on a web server being installed, the
//! tests run the two things any of them do themselves — the `git-http-backend`
//! CGI and a plain file server — from `tests/fixtures/`. SSH is deliberately not
//! simulated: pushing to a bare repo over `ssh://` needs no gitiup-specific code
//! (the transport is git's own, and the same ref writes go over it), and
//! `tests/host_git.rs` exercises every write through `file://`, which is the same
//! receive-pack on the other side.
//!
//! Everything skips itself when `python3` or `git-http-backend` is missing.

#[path = "support/conformance.rs"]
#[allow(dead_code)]
mod conformance;

use gitiup_host::hosts::git::GitHost;
use gitiup_host::{
    BlobStore, Host, HostErrorExt, HostErrorKind, Namespace, RefName, RefQuery, RefStore,
    RefUpdate, RemoteConfig,
};
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The web server, plus the port it ended up on.
struct Server {
    child: Child,
    port: u16,
}

impl Server {
    fn spawn(script: &str, args: &[&str], env: &[(&str, &Path)]) -> Option<Server> {
        let python = which("python3")?;
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(script);
        let mut command = Command::new(python);
        command
            .arg(&path)
            .args(args)
            .envs(env.iter().copied::<(&str, &Path)>())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().ok()?;
        // The fixture prints the port it bound before it serves anything.
        let announced = BufReader::new(child.stdout.take()?).lines().next()?.ok()?;
        let port = announced.trim().parse().ok()?;
        wait_until_listening(port).then_some(Server { child, port })
    }

    /// The CGI smart-HTTP server: `git-http-backend` behind a CGI contract.
    fn smart(root: &Path) -> Option<Server> {
        let backend = git_http_backend()?;
        Server::spawn(
            "git-http-backend.py",
            &["0"],
            &[
                ("GIT_HTTP_BACKEND", backend.as_path()),
                ("GIT_PROJECT_ROOT", root),
            ],
        )
    }

    /// The dumb transport: any static file server will do.
    fn static_files(root: &Path) -> Option<Server> {
        Server::spawn(
            "git-static.py",
            &[root.to_str()?, "0"],
            &[("PYTHONUNBUFFERED", Path::new("1"))],
        )
    }

    fn url(&self, repo: &str) -> String {
        format!("http://127.0.0.1:{}/{repo}.git", self.port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn which(program: &str) -> Option<PathBuf> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {program}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// `git-http-backend` is not on `PATH`; it lives beside the rest of git.
fn git_http_backend() -> Option<PathBuf> {
    let direct = Path::new("/usr/lib/git-core/git-http-backend");
    if direct.is_file() {
        return Some(direct.to_path_buf());
    }
    let out = Command::new("git").arg("--exec-path").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let exec_dir = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    let candidate = exec_dir.join("git-http-backend");
    candidate.is_file().then_some(candidate)
}

fn wait_until_listening(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// A bare repository served over HTTP, with a commit and a tag on it — the way
/// somebody publishes a project from a deploy key: an ordinary clone, then
/// `git push` at the bare repository.
fn served_repo(dir: &Path, name: &str) -> PathBuf {
    let repo = dir.join(format!("{name}.git"));
    gitiup_host::hosts::git::init_bare(&repo).expect("init bare");
    let work = dir.join(format!("{name}-work"));
    std::fs::create_dir_all(&work).expect("create worktree");
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(&work)
            .env("GIT_AUTHOR_NAME", "gitiup")
            .env("GIT_AUTHOR_EMAIL", "gitiup@example.com")
            .env("GIT_COMMITTER_NAME", "gitiup")
            .env("GIT_COMMITTER_EMAIL", "gitiup@example.com")
            .args(args)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(&["init", "-q", "."]);
    std::fs::write(work.join("README.md"), "# hosted on a web server\n").expect("write file");
    git(&["add", "README.md"]);
    git(&["commit", "-q", "-m", "first change"]);
    git(&["branch", "-M", "main"]);
    git(&["tag", "-a", "v1", "-m", "first release"]);
    git(&["push", "-q", &repo.to_string_lossy(), "--all"]);
    git(&["push", "-q", &repo.to_string_lossy(), "--tags"]);
    repo
}

/// `git config --file <repo>/config <key> <value>`, which is what a server
/// operator does to let anonymous pushes through.
fn repo_config(repo: &Path, key: &str, value: &str) {
    let out = Command::new("git")
        .args([
            "config",
            "--file",
            &repo.join("config").to_string_lossy(),
            key,
            value,
        ])
        .output()
        .expect("git config");
    assert!(
        out.status.success(),
        "git config {key}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Dumb HTTP needs `objects/info/packs` to exist; it is regenerated by hand after
/// anything is pushed.
fn update_server_info(repo: &Path) {
    let out = Command::new("git")
        .args(["--git-dir", &repo.to_string_lossy(), "update-server-info"])
        .output()
        .expect("update-server-info");
    assert!(
        out.status.success(),
        "update-server-info: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

struct Scratch {
    dir: tempfile::TempDir,
    repo: PathBuf,
    /// The name the repository is served under, and the default remote label.
    name: String,
}

impl Scratch {
    /// An empty bare repository: the state `gitiup init` expects.
    fn empty(name: &str) -> Self {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let repo = dir.path().join(format!("{name}.git"));
        gitiup_host::hosts::git::init_bare(&repo).expect("init bare");
        Scratch {
            dir,
            repo,
            name: name.to_string(),
        }
    }

    /// A repository that already has history, as a real project's would.
    fn served(name: &str) -> Self {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let repo = served_repo(dir.path(), name);
        Scratch {
            dir,
            repo,
            name: name.to_string(),
        }
    }

    /// This repository, over the given server.
    fn remote(&self, server: &Server) -> RemoteConfig {
        self.remote_as(server, &self.name.clone())
    }

    /// The same repository under another label, with its own mirror — another
    /// machine, as far as the store can tell.
    fn remote_as(&self, server: &Server, label: &str) -> RemoteConfig {
        self.remote_for(server, &self.name.clone(), label)
    }

    /// Another repository in the same served directory, under its own label. Each
    /// conformance body starts from "empty store", so each gets its own.
    fn remote_for(&self, server: &Server, repo: &str, label: &str) -> RemoteConfig {
        RemoteConfig::new(label, &server.url(repo))
            .expect("http url")
            .with_option("work-dir", self.work_dir(label))
            .with_option("ref-cache-ttl", "0s")
    }

    /// A fresh empty store in this server's directory, already initialised.
    fn fresh(&self, server: &Server, name: &str) -> GitHost {
        let repo = self.dir.path().join(format!("{name}.git"));
        gitiup_host::hosts::git::init_bare(&repo).expect("init bare");
        // Anonymous pushes are off by default on every git HTTP server, this one
        // included.
        repo_config(&repo, "http.receivepack", "true");
        GitHost::init(&self.remote_for(server, name, name)).expect("init over smart HTTP")
    }

    /// The same repository over the local filesystem, as its operator would use
    /// it.
    fn local(&self, label: &str) -> RemoteConfig {
        RemoteConfig::new(label, &format!("file://{}", self.repo.display()))
            .expect("file url")
            .with_option("work-dir", self.work_dir(label))
            .with_option("ref-cache-ttl", "0s")
    }

    fn work_dir(&self, label: &str) -> String {
        self.dir
            .path()
            .join(format!("mirror-{label}"))
            .display()
            .to_string()
    }
}

#[test]
fn a_full_gitiup_store_over_smart_http() {
    let scratch = Scratch::empty("publish");
    // What every real git HTTP server needs for an anonymous push; in these tests
    // the anonymous user is gitiup itself.
    repo_config(&scratch.repo, "http.receivepack", "true");
    let Some(server) = Server::smart(scratch.dir.path()) else {
        eprintln!("note: no python3 or git-http-backend, skipping smart HTTP tests");
        return;
    };
    // Each conformance body starts from an empty store, so each gets its own
    // repository; one server, one directory, several projects.
    conformance::describe_and_capabilities(&scratch.fresh(&server, "describe"));
    conformance::refs_round_trip(&scratch.fresh(&server, "refs"));
    conformance::blobs_round_trip(&scratch.fresh(&server, "blobs"));
    conformance::cas_conflicts_are_reported(&scratch.fresh(&server, "cas"));
    conformance::multi_ref_writes_are_all_or_nothing(&scratch.fresh(&server, "atomic"));

    let host = GitHost::init(&scratch.remote(&server)).expect("init over smart HTTP");
    // A change and the proof about it, published through the web server.
    let record = br#"{"id":"c1","base_ref":"refs/heads/main"}"#.to_vec();
    let record_oid = host
        .put_cas(&Namespace::CHANGE, &record)
        .expect("publish the change record");
    let proof = b"verified by the CI bot".to_vec();
    let proof_oid = host
        .put_cas(&Namespace::ATTESTATION, &proof)
        .expect("publish the proof");
    let change = RefName::change_head("c1").unwrap();
    let proof_ref = RefName::attestation(&proof_oid);
    host.update_refs_cas(&[
        RefUpdate::create(change.clone(), record_oid).with_actor("contributor"),
        RefUpdate::create(proof_ref.clone(), proof_oid).with_actor("ci-bot"),
    ])
    .expect("publish change and proof in one transaction");
    assert_eq!(host.get_ref(&change).unwrap().unwrap().oid, record_oid);

    // Anyone who can read the URL can see all of it, gitiup or not.
    let peer = GitHost::open(&scratch.remote_as(&server, "peer")).expect("open peer");
    assert_eq!(
        peer.get_ref(&change).unwrap().unwrap().oid,
        record_oid,
        "a second reader on the same URL sees the same change"
    );
    assert_eq!(peer.get(&proof_oid).unwrap().as_deref(), Some(&proof[..]));
    assert_eq!(
        peer.get_ref(&proof_ref).unwrap().unwrap().oid,
        proof_oid,
        "the proof is a ref anyone can see, not a private database row"
    );
    // The store's own machinery (the manifest, the record chains) stays out of an
    // ordinary ref listing, over HTTP as everywhere else.
    assert!(
        peer.list_refs(&RefQuery::all())
            .expect("list refs")
            .iter()
            .all(|entry| !entry.name.is_gitiup())
    );
    // Packs move the same way they do on a filesystem or a bucket.
    conformance::pack_round_trip(&host, &peer);
}

#[test]
fn a_static_http_server_hosts_a_read_only_store() {
    let scratch = Scratch::served("pub");
    update_server_info(&scratch.repo);
    let Some(server) = Server::static_files(scratch.dir.path()) else {
        eprintln!("note: no python3, skipping dumb HTTP tests");
        return;
    };

    // Somebody with write access publishes a change and its proof, then refreshes
    // the index file a dumb server hands out.
    let author = GitHost::open_or_init(&scratch.local("author")).expect("open locally");
    let record = b"a release, published from a deploy key".to_vec();
    let record_oid = author
        .put_cas(&Namespace::CHANGE, &record)
        .expect("publish the change record");
    author
        .update_ref_cas(&RefUpdate::create(
            RefName::change_head("rel-1").unwrap(),
            record_oid,
        ))
        .expect("publish the change");
    update_server_info(&scratch.repo);

    // The public mirror: readable by anyone, writable by nobody.
    let remote = scratch.remote(&server).with_option("read-only", "true");
    let host = GitHost::open(&remote).expect("open over dumb HTTP");
    let caps = host.capabilities();
    assert!(
        !caps.cas,
        "a static server cannot lease, so it must not claim CAS"
    );
    assert!(caps.immutable, "records are still records");
    assert_eq!(caps.missing(), vec!["cas", "atomic-multi-write"]);
    assert_eq!(
        host.get_ref(&RefName::change_head("rel-1").unwrap())
            .expect("resolve the change")
            .expect("the change is there")
            .oid,
        record_oid,
        "a change on a static server is as real as one on a forge"
    );
    assert_eq!(
        host.get(&record_oid).expect("read the record").unwrap(),
        record,
        "and its bytes came across in the fetch"
    );

    // It refuses before it even tries, and says which setting decided that.
    let error = host
        .update_ref_cas(&RefUpdate::create(
            RefName::branch("nope").unwrap(),
            record_oid,
        ))
        .expect_err("a read-only store refuses");
    assert_eq!(error.kind(), HostErrorKind::UnsupportedCas);
    assert!(
        error.hint().is_some_and(|hint| hint.contains("read-only")),
        "{error}"
    );
}

#[test]
fn pushing_to_a_static_server_is_reported_as_a_refused_write() {
    let scratch = Scratch::served("pub2");
    // A gitiup store with a record already in it, so the refusal this write gets is
    // the transport's and not "you are pointing a ref at bytes nobody published".
    let author = GitHost::open_or_init(&scratch.local("author")).expect("init the store");
    let record = author
        .put_cas(&Namespace::ATTESTATION, b"already in the store")
        .expect("publish a record");
    update_server_info(&scratch.repo);
    let Some(server) = Server::static_files(scratch.dir.path()) else {
        eprintln!("note: no python3, skipping dumb HTTP tests");
        return;
    };
    // Without the `read-only` setting the store cannot know it is read-only until
    // it tries to write, and the transport's refusal has to come back as the same
    // taxonomy a caller already handles, not as a mystery network failure.
    let host = GitHost::open(&scratch.remote(&server)).expect("open over dumb HTTP");
    assert!(
        host.capabilities().cas,
        "a plain HTTP origin looks writable until it is tried"
    );
    let error = host
        .update_ref_cas(&RefUpdate::create(RefName::attestation(&record), record))
        .expect_err("the server refuses the push");
    assert_eq!(
        error.kind(),
        HostErrorKind::UnsupportedCas,
        "a transport that cannot take a push is a capability answer, not a network failure"
    );
    assert!(!error.is_unreachable(), "{error}");
}

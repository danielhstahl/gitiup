//! The `fs` host: a bare directory plus a single `refs` file.
//!
//! This is the reference implementation every test in the workspace runs
//! against, and the layout the S3 host mirrors:
//!
//! ```text
//! <root>/
//!   gitiup-host.toml      manifest: schema-version, kind, store-prefix, created-at
//!   refs                  one line per ref: <oid>\t<name>\t<actor>\t<updated-at>
//!   packs/<oid>.pack      gitiup packs, content addressed
//!   cas/<ns>/<xx>/<hex>   content-addressed records (change, attestation, roster, job)
//! ```
//!
//! Because refs live in one file, the whole ref table is rewritten atomically
//! (temp file + `rename`) under a lock file, which gives the real
//! `atomic_multi_write` capability rather than an emulation. CAS objects are
//! written once and never modified, so `immutable` is true as well.
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dir = std::env::temp_dir().join("gitiup-host-fs-doc");
//! let _ = std::fs::remove_dir_all(&dir);
//! use gitiup_host::Host as _;
//! let host = gitiup_host::hosts::fs::FsHost::create(&dir)?;
//! assert_eq!(host.describe().kind, gitiup_host::HostKind::Fs);
//! # let _ = std::fs::remove_dir_all(&dir);
//! # Ok(()) }
//! ```

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::blob::{BlobEntry, BlobStore, Namespace, Prefix};
use crate::capability::{AuthModel, Capabilities, Host, HostInfo, HostKind};
use crate::config::{RemoteConfig, RemoteScheme};
use crate::error::{Conflict, HostError, HostResult, NotFound};
use crate::oid::Oid;
use crate::pack::{Pack, PackFormat, PackRequest};
use crate::refs::{Expect, Ref, RefDeletion, RefName, RefQuery, RefStore, RefUpdate};
use crate::time::Timestamp;

/// Name of the host manifest inside the directory.
pub const MANIFEST_FILE: &str = "gitiup-host.toml";

/// Name of the refs file.
pub const REFS_FILE: &str = "refs";

/// Name of the lock file used to serialise ref (and new-blob) writes.
pub const LOCK_FILE: &str = ".gitiup-lock";

/// Directory holding content-addressed records.
pub const CAS_DIR: &str = "cas";

/// Directory holding packs.
pub const PACKS_DIR: &str = "packs";

/// How long a lock may be held before another process may steal it.
const LOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for the lock before giving up.
const LOCK_WAIT: Duration = Duration::from_secs(5);

static LOCK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Manifest written into the host directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct HostManifest {
    schema_version: u32,
    kind: String,
    #[serde(default)]
    store_prefix: Option<String>,
    #[serde(default)]
    created_at: Option<Timestamp>,
}

/// A host stored in a plain directory on a filesystem you can `ls`.
#[derive(Debug, Clone)]
pub struct FsHost {
    root: PathBuf,
    name: String,
    store_prefix: String,
}

impl FsHost {
    /// Create a new, empty host at `root`.
    pub fn create(root: impl AsRef<Path>) -> HostResult<FsHost> {
        Self::create_with_prefix(root, crate::config::DEFAULT_STORE_PREFIX)
    }

    /// Create a new host with a specific store prefix.
    pub fn create_with_prefix(root: impl AsRef<Path>, store_prefix: &str) -> HostResult<FsHost> {
        let root = root.as_ref().to_path_buf();
        let store_prefix = crate::config::normalize_store_prefix(store_prefix)?;
        if root.join(MANIFEST_FILE).exists() {
            return Err(HostError::invalid(
                "host directory",
                format!("'{}' is already a gitiup host", root.display()),
            )
            .with_hint("open it with FsHost::open instead of creating it again"));
        }
        for dir in [root.as_path(), &root.join(CAS_DIR), &root.join(PACKS_DIR)] {
            std::fs::create_dir_all(dir)
                .map_err(|e| HostError::from_io("create host directory", dir, e))?;
        }
        let manifest = HostManifest {
            schema_version: crate::HOST_SCHEMA_VERSION,
            kind: "fs".to_string(),
            store_prefix: Some(store_prefix.clone()),
            created_at: Some(Timestamp::now()),
        };
        write_toml_atomic(&root.join(MANIFEST_FILE), &manifest)?;
        let host = FsHost {
            name: default_name(&root),
            root,
            store_prefix,
        };
        // Materialise an (empty) refs file so `ls` shows the interesting bits.
        host.write_refs(&[])?;
        Ok(host)
    }

    /// Open an existing host directory.
    pub fn open(root: impl AsRef<Path>) -> HostResult<FsHost> {
        let root = root.as_ref().to_path_buf();
        let path = root.join(MANIFEST_FILE);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            HostError::from_io("host manifest", &path, e).with_hint(format!(
                "create a host with FsHost::create('{}')",
                root.display()
            ))
        })?;
        let manifest: HostManifest = toml::from_str(&text).map_err(|e| {
            HostError::invalid(
                MANIFEST_FILE,
                format!("cannot parse {}: {e}", path.display()),
            )
        })?;
        if manifest.schema_version > crate::HOST_SCHEMA_VERSION_MAX {
            return Err(HostError::invalid(
                MANIFEST_FILE,
                format!(
                    "{} was written by a newer gitiup (schema-version {})",
                    path.display(),
                    manifest.schema_version
                ),
            )
            .with_hint(format!(
                "upgrade gitiup; this build understands schema-version {}",
                crate::HOST_SCHEMA_VERSION
            )));
        }
        if manifest.kind != "fs" {
            return Err(HostError::invalid(
                MANIFEST_FILE,
                format!(
                    "{} declares kind '{}', expected 'fs'",
                    path.display(),
                    manifest.kind
                ),
            ));
        }
        let store_prefix = manifest
            .store_prefix
            .clone()
            .unwrap_or_else(|| crate::config::DEFAULT_STORE_PREFIX.to_string());
        let host = FsHost {
            name: default_name(&root),
            root,
            store_prefix,
        };
        // Fail early on a corrupt refs file rather than mid-command.
        host.read_refs()?;
        Ok(host)
    }

    /// Open `root`, creating it when it is not a host yet.
    pub fn open_or_create(root: impl AsRef<Path>) -> HostResult<FsHost> {
        let root = root.as_ref();
        if root.join(MANIFEST_FILE).is_file() {
            FsHost::open(root)
        } else {
            FsHost::create(root)
        }
    }

    /// Build the host named by a `file://` remote.
    pub fn from_remote(remote: &RemoteConfig) -> HostResult<FsHost> {
        if remote.scheme() != RemoteScheme::File {
            return Err(HostError::SchemeUnknown(Box::new(
                crate::error::SchemeUnknown {
                    scheme: remote.scheme().as_str().to_string(),
                    supported: vec![RemoteScheme::File.as_str().to_string()],
                    hint: Some(format!(
                        "remote '{}' points at {}: the fs host only serves file:// remotes",
                        remote.name,
                        remote.redacted_url()
                    )),
                },
            )));
        }
        let mut host = FsHost::open_or_create(remote.url.file_path())?;
        host.name = remote.name.clone();
        host.store_prefix = remote.store_prefix.clone();
        Ok(host)
    }

    /// The directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path of the host manifest (useful for `gitiup doctor`).
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join(MANIFEST_FILE)
    }

    fn refs_path(&self) -> PathBuf {
        self.root.join(REFS_FILE)
    }

    fn lock_path(&self) -> PathBuf {
        self.root.join(LOCK_FILE)
    }

    fn cas_root(&self) -> PathBuf {
        self.root.join(CAS_DIR)
    }

    fn packs_dir(&self) -> PathBuf {
        self.root.join(PACKS_DIR)
    }

    fn pack_path(&self, oid: &Oid) -> PathBuf {
        self.packs_dir().join(format!("{}.pack", oid.hex()))
    }

    fn cas_path(&self, namespace: &Namespace, oid: &Oid) -> PathBuf {
        let hex = oid.hex();
        self.cas_root()
            .join(namespace.as_str())
            .join(&hex[..2])
            .join(&hex[2..])
    }

    /// Find where a blob lives (namespace + path), if it exists at all.
    pub fn locate(&self, oid: &Oid) -> HostResult<Option<(Namespace, PathBuf)>> {
        let hex = oid.hex();
        if hex.len() < 3 {
            return Ok(None);
        }
        let leaf = hex[2..].to_string();
        let entries = match std::fs::read_dir(self.cas_root()) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(HostError::from_io(
                    "list cas directory",
                    &self.cas_root(),
                    e,
                ));
            }
        };
        let mut names: Vec<String> = Vec::new();
        for entry in entries {
            let entry =
                entry.map_err(|e| HostError::from_io("list cas directory", &self.cas_root(), e))?;
            if entry.path().is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
                names.push(name.to_string());
            }
        }
        names.sort();
        for name in names {
            let namespace = match Namespace::new(name.clone()) {
                Ok(ns) => ns,
                Err(_) => continue, // a foreign directory in cas/: ignore it
            };
            let path = self.cas_root().join(&name).join(&hex[..2]).join(&leaf);
            if path.is_file() {
                return Ok(Some((namespace, path)));
            }
        }
        Ok(None)
    }

    /// Run `f` while holding the host lock.
    fn with_lock<T>(&self, f: impl FnOnce() -> HostResult<T>) -> HostResult<T> {
        let token = self.acquire_lock()?;
        let result = f();
        self.release_lock(&token);
        result
    }

    fn acquire_lock(&self) -> HostResult<PathBuf> {
        std::fs::create_dir_all(&self.root)
            .map_err(|e| HostError::from_io("create host directory", &self.root, e))?;
        let path = self.lock_path();
        let started = std::time::Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write as _;
                    let nonce = LOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
                    let _ = writeln!(
                        file,
                        "pid={} nonce={nonce} at={}",
                        std::process::id(),
                        Timestamp::now()
                    );
                    return Ok(path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(HostError::from_io("create lock file", &path, e));
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Err(HostError::denied(format!("lock {}", path.display())));
                }
                Err(_) => {
                    // Held by somebody: steal it if it looks abandoned.
                    if let Ok(meta) = std::fs::metadata(&path) {
                        let age = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.elapsed().ok())
                            .unwrap_or(Duration::ZERO);
                        if age > LOCK_TIMEOUT {
                            let _ = std::fs::remove_file(&path);
                            continue;
                        }
                    }
                    if started.elapsed() > LOCK_WAIT {
                        return Err(HostError::Storage(Box::new(crate::error::StorageError {
                            what: "acquire host lock".into(),
                            key: path.display().to_string(),
                            message: format!(
                                "another writer holds the lock (waited {}ms)",
                                LOCK_WAIT.as_millis()
                            ),
                            retryable: true,
                            source: None,
                        })));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    fn release_lock(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    /// Read the whole ref table, sorted by name.
    pub fn read_refs(&self) -> HostResult<Vec<Ref>> {
        let path = self.refs_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(HostError::from_io("read ref file", &path, e)),
        };
        let mut refs = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('\t');
            let (Some(oid_text), Some(name)) = (fields.next(), fields.next()) else {
                return Err(HostError::invalid(
                    REFS_FILE,
                    format!("{}:{} is not a ref line", path.display(), idx + 1),
                ));
            };
            let oid = Oid::from_hex(oid_text).map_err(|e| {
                HostError::invalid(
                    REFS_FILE,
                    format!("{}:{} has a bad oid: {}", path.display(), idx + 1, e),
                )
            })?;
            let name = RefName::new(name).map_err(|e| {
                HostError::invalid(
                    REFS_FILE,
                    format!("{}:{} has a bad ref name: {}", path.display(), idx + 1, e),
                )
            })?;
            let updated_by = fields
                .next()
                .filter(|s| !s.is_empty())
                .and_then(|s| crate::refs::Actor::new(s).ok());
            let updated_at = fields
                .next()
                .filter(|s| !s.is_empty())
                .and_then(|s| s.parse::<u64>().ok())
                .map(Timestamp::from_unix);
            refs.push(Ref {
                name,
                oid,
                updated_by,
                updated_at,
                schema: Some(crate::HOST_SCHEMA_VERSION),
            });
        }
        refs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(refs)
    }

    fn write_refs(&self, refs: &[Ref]) -> HostResult<()> {
        let mut text = format!("# gitiup refs (schema {})\n", crate::HOST_SCHEMA_VERSION);
        for reference in refs {
            text.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                reference.oid.hex(),
                reference.name,
                reference
                    .updated_by
                    .as_ref()
                    .map(|a| a.as_str())
                    .unwrap_or(""),
                reference
                    .updated_at
                    .map(|t| t.as_unix().to_string())
                    .unwrap_or_default(),
            ));
        }
        write_bytes_atomic(&self.refs_path(), text.as_bytes())
    }

    fn find_ref(&self, name: &crate::refs::RefName) -> HostResult<Option<Ref>> {
        Ok(self.read_refs()?.into_iter().find(|r| &r.name == name))
    }

    fn conflict_for(
        name: &crate::refs::RefName,
        expect: Expect,
        actual: Option<Oid>,
    ) -> Option<HostError> {
        if expect.matches(actual) {
            return None;
        }
        Some(HostError::Conflict(Box::new(Conflict {
            name: name.as_str().to_string(),
            expected: match expect {
                Expect::Absent => None,
                Expect::Is(oid) => Some(oid),
                Expect::Any => actual,
            },
            found: actual,
            actor: None,
            hint: Some(
                "the ref moved under us: re-read it, rebase the change and retry".to_string(),
            ),
        })))
    }

    fn store_blob(&self, namespace: &Namespace, content: &[u8], oid: &Oid) -> HostResult<PathBuf> {
        let path = self.cas_path(namespace, oid);
        if path.is_file() {
            return Ok(path);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| HostError::from_io("create cas directory", parent, e))?;
        }
        // Under the lock so two racing writers cannot both "win" the same oid
        // with different bytes on a filesystem without O_EXCL rename semantics.
        self.with_lock(|| {
            if path.is_file() {
                return Ok(());
            }
            let tmp = {
                let nonce = LOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
                path.with_extension(format!("tmp.{}.{}", std::process::id(), nonce))
            };
            std::fs::write(&tmp, content).map_err(|e| HostError::from_io("write blob", &tmp, e))?;
            if let Err(e) = std::fs::rename(&tmp, &path) {
                let _ = std::fs::remove_file(&tmp);
                return Err(HostError::from_io("store blob", &path, e));
            }
            Ok(())
        })?;
        // CAS integrity: the bytes we stored must hash back to the name.
        let read_back =
            std::fs::read(&path).map_err(|e| HostError::from_io("read blob", &path, e))?;
        if &Oid::hash_bytes(&read_back) != oid {
            return Err(HostError::Storage(Box::new(crate::error::StorageError {
                what: "verify blob".into(),
                key: path.display().to_string(),
                message: "stored content does not match its content address".into(),
                retryable: false,
                source: None,
            })));
        }
        Ok(path)
    }

    fn entry_for(&self, namespace: Namespace, oid: Oid, path: &Path) -> HostResult<BlobEntry> {
        let meta = std::fs::metadata(path).map_err(|e| HostError::from_io("stat blob", path, e))?;
        Ok(BlobEntry {
            namespace,
            oid,
            size: meta.len(),
            created_at: Some(Timestamp::from_file_modified(&meta)),
        })
    }
}

fn default_name(root: &Path) -> String {
    root.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| root.display().to_string())
}

fn write_toml_atomic<T: Serialize>(path: &Path, value: &T) -> HostResult<()> {
    let text = toml::to_string_pretty(value)
        .map_err(|e| HostError::invalid("host manifest", format!("cannot render: {e}")))?;
    write_bytes_atomic(path, text.as_bytes())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> HostResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| HostError::from_io("create directory", parent, e))?;
    }
    let nonce = LOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), nonce));
    let result = (|| -> HostResult<()> {
        let mut file = std::fs::File::create(&tmp)
            .map_err(|e| HostError::from_io("write temp file", &tmp, e))?;
        use std::io::Write as _;
        file.write_all(bytes)
            .map_err(|e| HostError::from_io("write temp file", &tmp, e))?;
        file.flush()
            .map_err(|e| HostError::from_io("flush temp file", &tmp, e))?;
        drop(file);
        std::fs::rename(&tmp, path).map_err(|e| HostError::from_io("replace file", path, e))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

impl RefStore for FsHost {
    fn list_refs(&self, query: &RefQuery) -> HostResult<Vec<Ref>> {
        let mut refs: Vec<Ref> = self
            .read_refs()?
            .into_iter()
            .filter(|r| query.matches(&r.name))
            .collect();
        if let Some(limit) = query.limit {
            refs.truncate(limit);
        }
        Ok(refs)
    }

    fn get_ref(&self, name: &crate::refs::RefName) -> HostResult<Option<Ref>> {
        self.find_ref(name)
    }

    fn update_ref_cas(&self, update: &RefUpdate) -> HostResult<Ref> {
        let written = self.with_lock(|| {
            let mut refs = self.read_refs()?;
            let actual = refs.iter().find(|r| r.name == update.name).map(|r| r.oid);
            if let Some(conflict) = Self::conflict_for(&update.name, update.expect, actual) {
                return Err(conflict);
            }
            let reference = Ref {
                name: update.name.clone(),
                oid: update.new,
                updated_by: update
                    .actor
                    .clone()
                    .or_else(|| Some(crate::refs::Actor::from_env())),
                updated_at: Some(Timestamp::now()),
                schema: Some(crate::HOST_SCHEMA_VERSION),
            };
            refs.retain(|r| r.name != reference.name);
            refs.push(reference.clone());
            refs.sort_by(|a, b| a.name.cmp(&b.name));
            self.write_refs(&refs)?;
            Ok(reference)
        })?;
        Ok(written)
    }

    /// All-or-nothing: the whole ref table is rewritten once, under one lock.
    fn update_refs_cas(&self, updates: &[RefUpdate]) -> HostResult<Vec<Ref>> {
        if updates.is_empty() {
            return Ok(Vec::new());
        }
        self.with_lock(|| {
            let mut refs = self.read_refs()?;
            // Validate every expectation against a working copy first, so a late
            // conflict cannot leave a partially applied batch.
            let mut working = refs.clone();
            let mut written = Vec::with_capacity(updates.len());
            for update in updates {
                let actual = working
                    .iter()
                    .find(|r| r.name == update.name)
                    .map(|r| r.oid);
                if let Some(conflict) = Self::conflict_for(&update.name, update.expect, actual) {
                    return Err(conflict);
                }
                let reference = Ref {
                    name: update.name.clone(),
                    oid: update.new,
                    updated_by: update
                        .actor
                        .clone()
                        .or_else(|| Some(crate::refs::Actor::from_env())),
                    updated_at: Some(Timestamp::now()),
                    schema: Some(crate::HOST_SCHEMA_VERSION),
                };
                working.retain(|r| r.name != reference.name);
                working.push(reference.clone());
                written.push(reference);
            }
            working.sort_by(|a, b| a.name.cmp(&b.name));
            refs.clear();
            refs.extend(working);
            self.write_refs(&refs)?;
            Ok(written)
        })
    }

    fn delete_ref_cas(&self, deletion: &RefDeletion) -> HostResult<()> {
        self.with_lock(|| {
            let mut refs = self.read_refs()?;
            let actual = refs.iter().find(|r| r.name == deletion.name).map(|r| r.oid);
            if actual.is_none() && matches!(deletion.expect, Expect::Is(_)) {
                return Err(HostError::NotFound(Box::new(NotFound {
                    what: "ref".into(),
                    key: deletion.name.to_string(),
                    hint: Some("it was already deleted; re-check the ref list".into()),
                })));
            }
            if let Some(conflict) = Self::conflict_for(&deletion.name, deletion.expect, actual) {
                return Err(conflict);
            }
            refs.retain(|r| r.name != deletion.name);
            self.write_refs(&refs)
        })
    }

    fn fetch_pack(&self, request: &PackRequest) -> HostResult<Pack> {
        if request.format != PackFormat::Raw {
            return Err(HostError::unsupported(
                format!("pack-format:{}", request.format.as_str()),
                "the fs host stores gitiup raw packs only; it has no git object database",
            )
            .with_hint("use the plain-git host (giti-xdw.3) for git packfiles"));
        }
        let have: Vec<Oid> = request.have.clone();
        let mut objects: Vec<(Namespace, Vec<u8>)> = Vec::new();
        let mut seen: Vec<Oid> = Vec::new();
        for want in &request.wants {
            if have.contains(want) {
                continue;
            }
            // A want may name a stored pack: expand it into its records.
            let path = self.pack_path(want);
            if path.is_file() {
                let bytes =
                    std::fs::read(&path).map_err(|e| HostError::from_io("read pack", &path, e))?;
                let pack = Pack {
                    format: PackFormat::Raw,
                    bytes,
                };
                for (ns, content) in pack.raw_objects()? {
                    let oid = Oid::hash_bytes(&content);
                    if have.contains(&oid) || seen.contains(&oid) {
                        continue;
                    }
                    seen.push(oid);
                    objects.push((ns, content));
                }
                continue;
            }
            let (namespace, path) = self.locate(want)?.ok_or_else(|| {
                HostError::NotFound(Box::new(NotFound {
                    what: "blob".into(),
                    key: want.hex(),
                    hint: Some(format!(
                        "'{}' is not in this host's CAS; push it first or check the digest",
                        want
                    )),
                }))
            })?;
            if seen.contains(want) {
                continue;
            }
            let content =
                std::fs::read(&path).map_err(|e| HostError::from_io("read blob", &path, e))?;
            if &Oid::hash_bytes(&content) != want {
                return Err(HostError::Storage(Box::new(crate::error::StorageError {
                    what: "verify blob".into(),
                    key: path.display().to_string(),
                    message: "stored content does not match its content address".into(),
                    retryable: false,
                    source: None,
                })));
            }
            seen.push(*want);
            objects.push((namespace, content));
        }
        Pack::from_raw_objects(objects)
    }

    fn put_pack(&self, pack: &Pack) -> HostResult<Oid> {
        pack.check_size()?;
        if pack.format != PackFormat::Raw {
            return Err(HostError::unsupported(
                format!("pack-format:{}", pack.format.as_str()),
                "the fs host cannot ingest git packfiles; it has no git object database",
            )
            .with_hint("use the plain-git host (giti-xdw.3), or convert to a raw pack"));
        }
        let objects = pack.raw_objects()?;
        let oid = pack.oid();
        let path = self.pack_path(&oid);
        std::fs::create_dir_all(self.packs_dir())
            .map_err(|e| HostError::from_io("create packs directory", &self.packs_dir(), e))?;
        if !path.is_file() {
            write_bytes_atomic(&path, &pack.bytes)?;
        }
        for (namespace, content) in &objects {
            let blob_oid = Oid::hash_bytes(content);
            self.store_blob(namespace, content, &blob_oid)?;
        }
        Ok(oid)
    }
}

impl BlobStore for FsHost {
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> HostResult<Oid> {
        let oid = Oid::hash_bytes(content);
        self.store_blob(namespace, content, &oid)?;
        Ok(oid)
    }

    fn get(&self, oid: &Oid) -> HostResult<Option<Vec<u8>>> {
        let Some((_, path)) = self.locate(oid)? else {
            return Ok(None);
        };
        let bytes = std::fs::read(&path).map_err(|e| HostError::from_io("read blob", &path, e))?;
        if &Oid::hash_bytes(&bytes) != oid {
            return Err(HostError::Storage(Box::new(crate::error::StorageError {
                what: "verify blob".into(),
                key: path.display().to_string(),
                message: "stored content does not match its content address".into(),
                retryable: false,
                source: None,
            })));
        }
        Ok(Some(bytes))
    }

    fn head(&self, oid: &Oid) -> HostResult<Option<BlobEntry>> {
        match self.locate(oid)? {
            None => Ok(None),
            Some((namespace, path)) => Ok(Some(self.entry_for(namespace, *oid, &path)?)),
        }
    }

    fn list_prefix(&self, pattern: &str) -> HostResult<Vec<BlobEntry>> {
        let prefix = Prefix::parse(pattern)?;
        let cas = self.cas_root();
        let mut out: Vec<BlobEntry> = Vec::new();
        let entries = match std::fs::read_dir(&cas) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(HostError::from_io("list cas directory", &cas, e)),
        };
        for entry in entries {
            let entry = entry.map_err(|e| HostError::from_io("list cas directory", &cas, e))?;
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(namespace) = Namespace::new(name.clone()) else {
                continue;
            };
            if let Some(want) = &prefix.namespace
                && want != &namespace
            {
                continue;
            }
            let ns_dir = entry.path();
            for shard in walk(&ns_dir)? {
                let bytes = std::fs::read(&shard)
                    .map_err(|e| HostError::from_io("read blob", &shard, e))?;
                let oid = Oid::hash_bytes(&bytes);
                if !prefix.matches(&namespace, &oid) {
                    continue;
                }
                out.push(self.entry_for(namespace.clone(), oid, &shard)?);
            }
        }
        out.sort_by_key(BlobEntry::key);
        Ok(out)
    }

    /// Forget a blob for real: this host is a directory the operator owns, so
    /// unlinking is what "retire it" means here.
    ///
    /// The one host in the workspace that can say yes. A git object database has no
    /// operation for "drop this object" and a versioned bucket's delete is a marker
    /// in front of bytes that stay forever, so they refuse and retention reports the
    /// refusal instead of a smaller disk usage.
    fn purge_cas(&self, oid: &Oid) -> HostResult<bool> {
        let Some((_, path)) = self.locate(oid)? else {
            return Ok(false);
        };
        std::fs::remove_file(&path).map_err(|e| HostError::from_io("purge blob", &path, e))?;
        // Leave no empty shard directories behind: a store that has been through a
        // retention run should still look like a store, not like a hash tree with
        // holes in it.
        if let Some(shard) = path.parent() {
            let _ = std::fs::remove_dir(shard);
        }
        Ok(true)
    }
}

impl Host for FsHost {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            cas: true,
            immutable: true,
            atomic_multi_write: true,
            auth: AuthModel::Filesystem,
        }
    }

    fn describe(&self) -> HostInfo {
        HostInfo {
            name: self.name.clone(),
            kind: HostKind::Fs,
            url: Some(format!("file://{}", self.root.display())),
            store_prefix: self.store_prefix.clone(),
            capabilities: self.capabilities(),
            implemented_by: crate::capability::implemented_by("fs"),
            schema_version: crate::HOST_SCHEMA_VERSION,
        }
    }
}

/// Collect the files under `dir` (one level of sharding deep).
fn walk(dir: &Path) -> HostResult<Vec<PathBuf>> {
    let mut out = Vec::new();
    let shards = match std::fs::read_dir(dir) {
        Ok(shards) => shards,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(HostError::from_io("list cas namespace", dir, e)),
    };
    for shard in shards {
        let shard = shard
            .map_err(|e| HostError::from_io("list cas namespace", dir, e))?
            .path();
        if shard.is_dir() {
            let leaves = match std::fs::read_dir(&shard) {
                Ok(leaves) => leaves,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(HostError::from_io("list cas shard", &shard, e)),
            };
            for leaf in leaves {
                let leaf = leaf
                    .map_err(|e| HostError::from_io("list cas shard", &shard, e))?
                    .path();
                if leaf.is_file() {
                    out.push(leaf);
                }
            }
        } else if shard.is_file() {
            out.push(shard);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HostErrorExt;

    fn host() -> FsHost {
        let dir = std::env::temp_dir().join(format!(
            "gitiup-fs-test-{}-{}",
            std::process::id(),
            LOCK_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        FsHost::create(&dir).unwrap()
    }

    #[test]
    fn manifest_is_written_and_reopenable() {
        let host = host();
        assert!(host.root().join(MANIFEST_FILE).is_file());
        assert!(host.root().join(REFS_FILE).is_file());
        let reopened = FsHost::open(host.root()).unwrap();
        assert_eq!(reopened.describe().name, host.describe().name);
        assert_eq!(reopened.describe().store_prefix, "gitiup");
        assert!(FsHost::create(host.root()).is_err(), "must not clobber");
        let _ = std::fs::remove_dir_all(host.root());
    }

    #[test]
    fn from_remote_rejects_non_file_urls() {
        let remote = RemoteConfig::new("origin", "s3://bucket/repo").unwrap();
        let err = FsHost::from_remote(&remote).unwrap_err();
        assert_eq!(err.kind(), crate::HostErrorKind::SchemeUnknown);
        assert!(err.to_string().contains("s3"), "{err}");
    }

    #[test]
    fn refs_round_trip_through_disk() {
        let host = host();
        let oid = host.put_cas(&Namespace::RECORD, b"x").unwrap();
        let name = RefName::branch("main").unwrap();
        let written = host
            .update_ref_cas(
                &RefUpdate::create(name.clone(), oid)
                    .with_actor("ada")
                    .with_message("first"),
            )
            .unwrap();
        assert_eq!(written.oid, oid);
        assert_eq!(written.updated_by.as_ref().unwrap().as_str(), "ada");
        let read_back = host.get_ref(&name).unwrap().unwrap();
        assert_eq!(read_back, written);
        assert_eq!(host.list_refs(&RefQuery::all()).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(host.root());
    }

    #[test]
    fn concurrent_create_only_writes_produce_one_winner() {
        let host = host();
        let oid = host.put_cas(&Namespace::RECORD, b"y").unwrap();
        let name = RefName::branch("race").unwrap();
        let mut handles = Vec::new();
        for i in 0..8 {
            let host = host.clone();
            let name = name.clone();
            handles.push(std::thread::spawn(move || {
                let res = host.update_ref_cas(
                    &RefUpdate::create(name, oid).with_actor(format!("worker-{i}")),
                );
                res.is_ok()
            }));
        }
        let winners = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(winners, 1, "exactly one create-only write may win");
        assert_eq!(host.list_refs(&RefQuery::all()).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(host.root());
    }

    #[test]
    fn atomic_batch_rejects_late_conflict_without_writing() {
        let host = host();
        let a = host.put_cas(&Namespace::RECORD, b"a").unwrap();
        let b = host.put_cas(&Namespace::RECORD, b"b").unwrap();
        let other = host.put_cas(&Namespace::RECORD, b"other").unwrap();
        let head = RefName::change_head("c1").unwrap();
        let live = RefName::branch("main").unwrap();
        host.update_ref_cas(&RefUpdate::create(live.clone(), other))
            .unwrap();
        let batch = vec![
            RefUpdate::create(head.clone(), a),
            RefUpdate::replace(live.clone(), Oid::from_hex("dead").unwrap(), b),
        ];
        let err = host.update_refs_cas(&batch).unwrap_err();
        assert!(err.is_conflict(), "{err}");
        assert!(
            host.get_ref(&head).unwrap().is_none(),
            "the first update must have been rolled back"
        );
        assert_eq!(host.get_ref(&live).unwrap().unwrap().oid, other);
        let _ = std::fs::remove_dir_all(host.root());
    }
}

//! The slice of S3 the bucket-as-forge host actually uses, and an in-process
//! implementation of it.
//!
//! [`Bucket`] is deliberately *not* "the S3 API": it is the handful of
//! operations a git-forge-in-a-bucket needs — read, head, conditionally write,
//! list, write a large object — plus the three bucket facts the host turns into
//! [`Capabilities`](crate::Capabilities). Keeping it that small is what lets
//! the whole host be tested without an S3 endpoint: [`MemoryBucket`] is a real
//! (in-memory) implementation of the same contract — etags, conditional writes,
//! paged listings, staged multipart uploads — so `tests/host_s3.rs` exercises
//! the production code path rather than a mock of it.
//!
//! Note what is **missing**: there is no delete. Nothing gitiup writes is ever
//! removed — refs are tombstoned, objects are content-addressed, and bucket
//! versioning is what protects history. See [the S3 host](super).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::error::{HostError, HostErrorKind};
use crate::oid::Oid;
use crate::time::Timestamp;

/// Largest number of keys one S3 LIST round-trip may return.
pub const MAX_LISTING_KEYS: usize = 1000;

/// Metadata for one stored object — what HEAD/LIST know without a GET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    /// Full object key, e.g. `my-repo/gitiup/refs/heads/main`.
    pub key: String,
    /// Size in bytes.
    pub size: u64,
    /// The stored object's etag, quoted exactly as S3 returns it. This is the
    /// token a later compare-and-swap hands back as `If-Match`.
    pub etag: String,
    /// Last modification time, when the backend reports one.
    pub modified: Option<Timestamp>,
}

/// A stored object read back whole, with the etag needed to CAS it later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// Full object key.
    pub key: String,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// Etag of exactly these bytes.
    pub etag: String,
}

impl Object {
    /// Metadata for this object.
    pub fn meta(&self) -> ObjectMeta {
        ObjectMeta {
            key: self.key.clone(),
            size: self.bytes.len() as u64,
            etag: self.etag.clone(),
            modified: None,
        }
    }
}

/// What must hold about the stored object for a PUT to land.
///
/// This is the S3 half of [`Expect`](crate::Expect): [`PutCond::CreateOnly`] is
/// `If-None-Match: *`, [`PutCond::IfMatch`] is `If-Match: <etag>`, and
/// [`PutCond::Unconditional`] is a plain PUT — which is exactly why gitiup code
/// that gates a merge never uses it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PutCond {
    /// Plain `PUT` — overwrite whatever is there.
    #[default]
    Unconditional,
    /// `If-None-Match: *` — fail with
    /// [`BucketError::PreconditionFailed`] if the key already exists.
    CreateOnly,
    /// `If-Match: <etag>` — fail unless the stored object still carries this
    /// exact etag.
    IfMatch(String),
}

impl PutCond {
    /// Whether this write depends on conditional-write support.
    pub fn is_conditional(&self) -> bool {
        !matches!(self, PutCond::Unconditional)
    }

    /// The header form, for logs and error messages.
    pub fn describe(&self) -> String {
        match self {
            PutCond::Unconditional => "plain PUT".to_string(),
            PutCond::CreateOnly => "If-None-Match: *".to_string(),
            PutCond::IfMatch(etag) => format!("If-Match: {etag}"),
        }
    }
}

/// Object versioning state of a bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersioningState {
    /// Every overwrite keeps the previous version — what gitiup requires.
    Enabled,
    /// Versioning was on and is now off: existing versions are still kept.
    Suspended,
    /// Nothing is versioned, so an overwrite destroys history.
    Disabled,
    /// The endpoint did not say.
    Unknown,
}

impl VersioningState {
    /// Stable name for `--json` output.
    pub fn as_str(self) -> &'static str {
        match self {
            VersioningState::Enabled => "enabled",
            VersioningState::Suspended => "suspended",
            VersioningState::Disabled => "disabled",
            VersioningState::Unknown => "unknown",
        }
    }

    /// Whether overwriting an object can lose data.
    pub fn protects_history(self) -> bool {
        matches!(self, VersioningState::Enabled | VersioningState::Suspended)
    }
}

impl fmt::Display for VersioningState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the host found out about the bucket at connect time.
///
/// These facts *become* the host's capabilities: an unversioned bucket cannot
/// promise immutability, and a bucket without conditional writes cannot promise
/// compare-and-swap, so owner-side merges are refused there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketFacts {
    /// Object versioning state.
    pub versioning: VersioningState,
    /// Whether Object Lock / retention is configured (recommended, not required).
    pub object_lock: bool,
    /// Whether conditional writes (`If-Match` / `If-None-Match`) work.
    pub conditional_writes: bool,
}

impl BucketFacts {
    /// What a backend that will not say anything reports.
    pub const fn unknown() -> BucketFacts {
        BucketFacts {
            versioning: VersioningState::Unknown,
            object_lock: false,
            conditional_writes: false,
        }
    }

    /// Whether refs can be advanced safely here.
    pub fn cas(&self) -> bool {
        self.conditional_writes
    }

    /// Human-readable advice for `gitiup remote doctor`.
    pub fn advice(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.versioning.protects_history() {
            out.push(
                "object versioning is off, so overwriting a record destroys it: \
                 this host cannot promise immutability — enable versioning on the bucket"
                    .to_string(),
            );
        }
        if !self.conditional_writes {
            out.push(
                "this bucket does not support conditional writes (If-Match / If-None-Match), \
                 so ref updates cannot be compare-and-swap and gitiup refuses owner-side merges"
                    .to_string(),
            );
        }
        if self.conditional_writes && !self.object_lock {
            out.push(
                "Object Lock / retention is not configured: recommended so attestations cannot \
                 be removed before their retention window"
                    .to_string(),
            );
        }
        out
    }
}

/// Where a bucket lives and how we authenticated to it, for logs and
/// `gitiup remote show`. Never carries a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketInfo {
    /// Bucket name.
    pub bucket: String,
    /// Endpoint the client talks to (`s3`, or an explicit URL for MinIO & co).
    pub endpoint: String,
    /// Region the client resolved.
    pub region: String,
    /// Where the credentials came from, described but never printed in full.
    pub credentials: String,
}

impl fmt::Display for BucketInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "s3://{} ({} @ {}, credentials: {})",
            self.bucket, self.region, self.endpoint, self.credentials
        )
    }
}

/// Transport failure, before it is mapped onto the [host error
/// taxonomy](crate::error).
///
/// The mapping is one-to-one, so a transport can be written without knowing
/// anything about refs: 404 is `NotFound`, 401/403 is `PermissionDenied`, 412 is
/// a CAS signal, "this bucket cannot do that" is `UnsupportedCas`, and anything
/// that smells like the network is `Unreachable`.
#[derive(Debug)]
pub enum BucketError {
    /// The key is not there (S3 404 / `NoSuchKey`).
    NotFound {
        /// Key that was missing.
        key: String,
    },
    /// A conditional write did not hold (S3 412).
    PreconditionFailed {
        /// Key we tried to write.
        key: String,
        /// The condition that failed, rendered as a header.
        condition: String,
    },
    /// 401/403: reached the bucket, not allowed.
    Denied {
        /// Key or bucket involved.
        key: String,
        /// What the endpoint said.
        message: String,
    },
    /// The bucket (or this endpoint) cannot do the operation at all.
    Unsupported {
        /// Feature name, e.g. `conditional-writes` or `multipart`.
        feature: String,
        /// What the endpoint said.
        message: String,
    },
    /// Connection, DNS, TLS or timeout trouble.
    Unreachable {
        /// What happened.
        message: String,
        /// Whether another attempt could plausibly work.
        retryable: bool,
    },
    /// Anything else, with as much context as the transport has.
    Other {
        /// Key or bucket involved.
        key: String,
        /// What happened.
        message: String,
    },
}

impl BucketError {
    /// The taxonomy this failure maps to.
    pub fn kind(&self) -> HostErrorKind {
        match self {
            BucketError::NotFound { .. } => HostErrorKind::NotFound,
            BucketError::PreconditionFailed { .. } => HostErrorKind::Conflict,
            BucketError::Denied { .. } => HostErrorKind::PermissionDenied,
            BucketError::Unsupported { .. } => HostErrorKind::UnsupportedCas,
            BucketError::Unreachable { .. } => HostErrorKind::Unreachable,
            BucketError::Other { .. } => HostErrorKind::Storage,
        }
    }

    /// Whether retrying the same call could work.
    pub fn is_retryable(&self) -> bool {
        match self {
            BucketError::Unreachable { retryable, .. } => *retryable,
            BucketError::PreconditionFailed { .. } => true,
            _ => false,
        }
    }

    /// The key involved, if any.
    pub fn key(&self) -> Option<&str> {
        match self {
            BucketError::NotFound { key }
            | BucketError::PreconditionFailed { key, .. }
            | BucketError::Denied { key, .. }
            | BucketError::Other { key, .. } => Some(key),
            BucketError::Unsupported { .. } | BucketError::Unreachable { .. } => None,
        }
    }

    /// Whether this says "conditional writes are not a thing here" rather than
    /// "this particular write lost a race" — the difference between degrading the
    /// host to `cas = false` and retrying.
    pub fn is_conditional_unsupported(&self) -> bool {
        self.unsupported_feature()
            .is_some_and(|feature| feature == "conditional-writes")
    }

    /// Whether this is a 412: the precondition did not hold, which for a
    /// content-addressed write usually means somebody else wrote the same bytes.
    pub fn is_precondition_failed(&self) -> bool {
        matches!(self, BucketError::PreconditionFailed { .. })
    }

    /// The feature named by an [`BucketError::Unsupported`], if that is what this
    /// is.
    pub fn unsupported_feature(&self) -> Option<&str> {
        match self {
            BucketError::Unsupported { feature, .. } => Some(feature),
            _ => None,
        }
    }
}

impl fmt::Display for BucketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BucketError::NotFound { key } => write!(f, "object {key} not found"),
            BucketError::PreconditionFailed { key, condition } => {
                write!(f, "conditional write on {key} failed ({condition})")
            }
            BucketError::Denied { key, message } => {
                write!(f, "not allowed to access {key}: {message}")
            }
            BucketError::Unsupported { feature, message } => {
                write!(f, "{feature} is not supported here: {message}")
            }
            BucketError::Unreachable { message, .. } => {
                write!(f, "bucket unreachable: {message}")
            }
            BucketError::Other { key, message } => write!(f, "{key}: {message}"),
        }
    }
}

impl From<BucketError> for HostError {
    fn from(err: BucketError) -> HostError {
        match err {
            BucketError::NotFound { key } => HostError::not_found("object", key).with_hint(
                "gitiup objects are written once and never deleted; a missing one was never pushed",
            ),
            // A bare 412 that escapes a CAS loop is still "what you assumed is
            // not true any more", which is the taxonomy's Conflict.
            BucketError::PreconditionFailed { key, condition } => {
                HostError::conflict(key, None, None)
                    .with_hint(format!("re-read the object and retry: {condition} did not hold"))
            }
            BucketError::Denied { key, message } => {
                HostError::denied(format!("access {key} ({message})")).with_hint(
                    "check the bucket policy and the credential chain (env, profile, SSO, web identity)",
                )
            }
            BucketError::Unsupported { feature, message } => HostError::unsupported(feature, message),
            BucketError::Unreachable { message, retryable } => {
                // A reset connection is worth another try; an endpoint that
                // answered "no such bucket" is not, and pretending otherwise
                // turns a typo into a retry storm.
                HostError::Unreachable(Box::new(crate::error::Unreachable {
                    endpoint: None,
                    message,
                    retryable,
                    hint: None,
                    source: None,
                }))
            }
            BucketError::Other { key, message } => {
                HostError::Storage(Box::new(crate::error::StorageError {
                    what: "S3 operation".into(),
                    key,
                    message,
                    retryable: false,
                    source: None,
                }))
            }
        }
    }
}

/// The bucket operations [`S3Host`](super) is built from.
///
/// Implementations must be `Send + Sync` (a verification run reads several
/// buckets on threads) and must behave like S3 in the three ways the host
/// depends on:
///
/// * **etags** identify the exact stored bytes, and a conditional write against
///   a stale etag fails with [`BucketError::PreconditionFailed`] *without*
///   changing anything;
/// * **LIST is read-after-write consistent** — an object is listed only once a
///   GET would succeed, and keys come back in lexicographic order;
/// * **nothing is deleted**: this trait has no delete, and a backend that evicts
///   objects must not claim versioning or Object Lock it does not have.
pub trait Bucket: Send + Sync {
    /// Who this is, for `describe()` and error hints. Cheap.
    fn info(&self) -> BucketInfo;

    /// The three facts that become the host's capabilities. Called once at
    /// connect time; may cost a few requests.
    fn facts(&self) -> Result<BucketFacts, BucketError>;

    /// Read an object. `Ok(None)` when the key is absent.
    fn get(&self, key: &str) -> Result<Option<Object>, BucketError>;

    /// Metadata only. `Ok(None)` when the key is absent.
    fn head(&self, key: &str) -> Result<Option<ObjectMeta>, BucketError>;

    /// Write `bytes` at `key`, honouring `cond`.
    ///
    /// A conditional write must not touch the stored object when the condition
    /// fails. A backend that cannot honour conditional writes at all must answer
    /// [`BucketError::Unsupported`] — that is what degrades a host to
    /// `capabilities.cas = false`.
    fn put(&self, key: &str, bytes: &[u8], cond: PutCond) -> Result<ObjectMeta, BucketError>;

    /// Every key under `prefix`, lexicographic, across as many LIST round-trips
    /// as it takes.
    fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, BucketError>;

    /// Write a large object. Implementations should use the real multipart
    /// machinery (create / upload-part / complete, aborting on failure) so a
    /// half-finished upload leaves no partial object behind.
    fn put_large(
        &self,
        key: &str,
        bytes: &[u8],
        part_size: usize,
        cond: PutCond,
    ) -> Result<ObjectMeta, BucketError> {
        let _ = part_size;
        self.put(key, bytes, cond)
    }

    /// Multipart parts may not be smaller than this (S3's own minimum).
    fn min_part_size(&self) -> usize {
        5 * 1024 * 1024
    }
}

/// A bucket behind an `Arc`, so an [`S3Host`](super::S3Host) stays `Clone`.
pub type SharedBucket = Arc<dyn Bucket>;

/// The etag S3 gives a single-part object: quoted 32-hex-digit MD5.
///
/// gitiup's content *address* is always SHA-256; the etag is the transport's own
/// identity token and only has to be stable, content-derived and opaque.
pub fn single_part_etag(bytes: &[u8]) -> String {
    format!("\"{}\"", Oid::hash_bytes(bytes).short(32))
}

/// The etag S3 gives a multipart object: `<digest of part digests>-<count>`.
pub fn multipart_etag(parts: &[Vec<u8>]) -> String {
    let mut joined = Vec::new();
    for part in parts {
        joined.extend_from_slice(&Oid::hash_bytes(part).as_bytes()[..16]);
    }
    format!("\"{}-{}\"", Oid::hash_bytes(&joined).short(32), parts.len())
}

/// Exponential backoff for a lost compare-and-swap race: `base << attempt`,
/// capped. Shared by the CAS path and the tests so the numbers cannot drift.
pub fn backoff(attempt: u32, base: Duration, cap: Duration) -> Duration {
    let factor = 1u32.checked_shl(attempt).unwrap_or(1 << 16);
    base.saturating_mul(factor).min(cap)
}

// ---------------------------------------------------------------------------
// The in-process bucket
// ---------------------------------------------------------------------------

/// Counters a [`MemoryBucket`] keeps, so tests can assert *how* the host used
/// the bucket — multipart for big packs, no LIST/GET on a cache hit, a ref
/// deletion that touched no object — and not only that data came back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BucketStats {
    /// Successful PUTs (single-part or the completion of a multipart upload).
    pub puts: usize,
    /// Conditional writes attempted.
    pub conditional_puts: usize,
    /// Conditional writes refused with 412.
    pub precondition_failures: usize,
    /// Successful `put_large` calls.
    pub multipart_uploads: usize,
    /// Parts uploaded across them.
    pub parts: usize,
    /// GET requests.
    pub gets: usize,
    /// HEAD requests.
    pub heads: usize,
    /// LIST round-trips (one per page).
    pub lists: usize,
}

impl BucketStats {
    /// Render as a `key=value` line for test failure messages.
    pub fn summary(&self) -> String {
        format!(
            "puts={} conditional={} conflicts={} multipart={} parts={} gets={} heads={} lists={}",
            self.puts,
            self.conditional_puts,
            self.precondition_failures,
            self.multipart_uploads,
            self.parts,
            self.gets,
            self.heads,
            self.lists
        )
    }
}

/// Configuration of a [`MemoryBucket`].
#[derive(Debug, Clone)]
pub struct MemoryBucketConfig {
    /// Bucket name reported in [`BucketInfo`].
    pub bucket: String,
    /// Whether the fake supports `If-Match` / `If-None-Match`.
    pub conditional_writes: bool,
    /// Object versioning state the fake reports.
    pub versioning: VersioningState,
    /// Whether Object Lock is reported as configured.
    pub object_lock: bool,
    /// How many keys a single LIST page returns (S3 allows at most 1000).
    pub page_size: usize,
}

impl Default for MemoryBucketConfig {
    fn default() -> Self {
        MemoryBucketConfig {
            bucket: "gitiup-forge".to_string(),
            conditional_writes: true,
            versioning: VersioningState::Enabled,
            object_lock: false,
            page_size: MAX_LISTING_KEYS,
        }
    }
}

impl MemoryBucketConfig {
    /// Point the fake at a bucket name (builder style).
    pub fn with_bucket(mut self, name: &str) -> MemoryBucketConfig {
        self.bucket = name.to_string();
        self
    }

    /// Set the page size fake LISTs use.
    pub fn with_page_size(mut self, page: usize) -> MemoryBucketConfig {
        self.page_size = page.max(1);
        self
    }

    /// Report Object Lock as configured.
    pub fn with_object_lock(mut self, locked: bool) -> MemoryBucketConfig {
        self.object_lock = locked;
        self
    }

    /// A bucket that refuses conditional writes — an old S3 or a stripped-down
    /// gateway, the case that must degrade to `cas = false`.
    pub fn without_conditional_writes() -> MemoryBucketConfig {
        MemoryBucketConfig {
            conditional_writes: false,
            ..Default::default()
        }
    }

    /// A bucket with versioning off — records are not immutable there.
    pub fn unversioned() -> MemoryBucketConfig {
        MemoryBucketConfig {
            versioning: VersioningState::Disabled,
            ..Default::default()
        }
    }
}

#[derive(Debug)]
struct StoredObject {
    bytes: Vec<u8>,
    etag: String,
    modified: Timestamp,
    versions: u32,
}

#[derive(Debug)]
struct Upload {
    parts: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
struct MemoryState {
    objects: BTreeMap<String, StoredObject>,
    uploads: BTreeMap<String, Upload>,
    next_upload: u64,
    stats: BucketStats,
    fail_conditionals: usize,
    lose_races: usize,
    /// `None` = off; otherwise, let this many more writes through and fail every
    /// write after that.
    lose_writes_after: Option<usize>,
}

/// An in-process S3 bucket: real etags, real conditional-write semantics, real
/// paged listings and staged multipart uploads, no network.
///
/// This is not a mock of the host — it is a second implementation of the
/// transport contract, so an `S3Host` running on it is production code
/// exercised end to end. Cloning shares the same objects, which is how two
/// "clones" of one bucket are built in the convergence tests.
#[derive(Debug, Clone, Default)]
pub struct MemoryBucket {
    config: Arc<MemoryBucketConfig>,
    state: Arc<Mutex<MemoryState>>,
}

impl MemoryBucket {
    /// A bucket with the given config.
    pub fn new(config: MemoryBucketConfig) -> MemoryBucket {
        MemoryBucket {
            config: Arc::new(config),
            state: Arc::new(Mutex::new(MemoryState::default())),
        }
    }

    /// A versioned bucket with conditional writes: a well-configured S3 bucket,
    /// and the default.
    pub fn forge(name: &str) -> MemoryBucket {
        MemoryBucket::new(MemoryBucketConfig::default().with_bucket(name))
    }

    /// A bucket that cannot do conditional writes.
    pub fn without_conditional_writes(name: &str) -> MemoryBucket {
        MemoryBucket::new(MemoryBucketConfig::without_conditional_writes().with_bucket(name))
    }

    /// A bucket without object versioning.
    pub fn unversioned(name: &str) -> MemoryBucket {
        MemoryBucket::new(MemoryBucketConfig::unversioned().with_bucket(name))
    }

    /// Refuse the next `n` conditional writes with 412, as if another writer had
    /// won every race.
    pub fn fail_next_conditionals(&self, n: usize) {
        self.lock().fail_conditionals = n;
    }

    /// Refuse the next `n` conditional writes with 412 even though the etag
    /// still matches — the "412 that a re-read clears" case, which the host is
    /// supposed to retry with backoff.
    pub fn lose_next_races(&self, n: usize) {
        self.lock().lose_races = n;
    }

    /// Let `allowed` more writes through, then fail every write after that with
    /// an unreachable-transport error: the "the connection dropped halfway
    /// through the batch" case, which is what makes a rollback best effort
    /// rather than a promise.
    pub fn fail_writes_after(&self, allowed: usize) {
        self.lock().lose_writes_after = Some(allowed);
    }

    /// Request counters since the bucket was created.
    pub fn stats(&self) -> BucketStats {
        self.lock().stats
    }

    /// Reset the counters (not the objects).
    pub fn reset_stats(&self) {
        self.lock().stats = BucketStats::default();
    }

    /// Every key currently stored, sorted.
    pub fn keys(&self) -> Vec<String> {
        self.lock().objects.keys().cloned().collect()
    }

    /// How many objects have been written at `key` (1 = one PUT; more means
    /// overwrites, which only versioning makes safe).
    pub fn versions(&self, key: &str) -> u32 {
        self.lock()
            .objects
            .get(key)
            .map(|object| object.versions)
            .unwrap_or(0)
    }

    /// Raw bytes at `key`, for layout assertions.
    pub fn raw(&self, key: &str) -> Option<Vec<u8>> {
        self.lock()
            .objects
            .get(key)
            .map(|object| object.bytes.clone())
    }

    /// How many keys hold something. A ref deletion must not shrink this.
    pub fn object_count(&self) -> usize {
        self.lock().objects.len()
    }

    /// Multipart uploads started and never completed or aborted — a host that
    /// abandons an upload leaks storage the bill will still show.
    pub fn open_uploads(&self) -> usize {
        self.lock().uploads.len()
    }

    fn lock(&self) -> MutexGuard<'_, MemoryState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn meta_of(key: &str, object: &StoredObject) -> ObjectMeta {
        ObjectMeta {
            key: key.to_string(),
            size: object.bytes.len() as u64,
            etag: object.etag.clone(),
            modified: Some(object.modified),
        }
    }

    /// Would this write land? Bumps the conflict counters when it would not.
    fn evaluate(
        &self,
        state: &mut MemoryState,
        key: &str,
        cond: &PutCond,
    ) -> Result<(), BucketError> {
        if !cond.is_conditional() {
            return Ok(());
        }
        state.stats.conditional_puts += 1;
        let fail = |state: &mut MemoryState, cond: &PutCond| {
            state.stats.precondition_failures += 1;
            Err(BucketError::PreconditionFailed {
                key: key.to_string(),
                condition: cond.describe(),
            })
        };
        if !self.config.conditional_writes {
            return Err(BucketError::Unsupported {
                feature: "conditional-writes".to_string(),
                message: format!(
                    "{key}: bucket {} does not support conditional requests ({})",
                    self.config.bucket,
                    cond.describe()
                ),
            });
        }
        if state.fail_conditionals > 0 {
            state.fail_conditionals -= 1;
            return fail(state, cond);
        }
        if state.lose_races > 0 {
            state.lose_races -= 1;
            return fail(state, cond);
        }
        match cond {
            PutCond::CreateOnly if state.objects.contains_key(key) => fail(state, cond),
            PutCond::IfMatch(want)
                if !state
                    .objects
                    .get(key)
                    .is_some_and(|object| etag_eq(&object.etag, want)) =>
            {
                fail(state, cond)
            }
            _ => Ok(()),
        }
    }

    fn store(&self, state: &mut MemoryState, key: &str, bytes: &[u8], etag: String) -> ObjectMeta {
        let versions = state
            .objects
            .get(key)
            .map(|object| object.versions + 1)
            .unwrap_or(1);
        let object = StoredObject {
            bytes: bytes.to_vec(),
            etag,
            modified: Timestamp::now(),
            versions,
        };
        let meta = Self::meta_of(key, &object);
        state.objects.insert(key.to_string(), object);
        state.stats.puts += 1;
        meta
    }
}

fn etag_eq(a: &str, b: &str) -> bool {
    a.trim_matches('"') == b.trim_matches('"')
}

impl Bucket for MemoryBucket {
    fn info(&self) -> BucketInfo {
        BucketInfo {
            bucket: self.config.bucket.clone(),
            endpoint: "in-memory".to_string(),
            region: "memory-1".to_string(),
            credentials: "none (in-process)".to_string(),
        }
    }

    fn facts(&self) -> Result<BucketFacts, BucketError> {
        Ok(BucketFacts {
            versioning: self.config.versioning,
            object_lock: self.config.object_lock,
            conditional_writes: self.config.conditional_writes,
        })
    }

    fn get(&self, key: &str) -> Result<Option<Object>, BucketError> {
        let mut state = self.lock();
        state.stats.gets += 1;
        Ok(state.objects.get(key).map(|object| Object {
            key: key.to_string(),
            bytes: object.bytes.clone(),
            etag: object.etag.clone(),
        }))
    }

    fn head(&self, key: &str) -> Result<Option<ObjectMeta>, BucketError> {
        let mut state = self.lock();
        state.stats.heads += 1;
        Ok(state
            .objects
            .get(key)
            .map(|object| Self::meta_of(key, object)))
    }

    fn put(&self, key: &str, bytes: &[u8], cond: PutCond) -> Result<ObjectMeta, BucketError> {
        let mut state = self.lock();
        if let Some(remaining) = state.lose_writes_after {
            if remaining == 0 {
                return Err(BucketError::Unreachable {
                    message: format!("{key}: the connection dropped before the write landed"),
                    retryable: true,
                });
            }
            state.lose_writes_after = Some(remaining - 1);
        }
        self.evaluate(&mut state, key, &cond)?;
        let etag = single_part_etag(bytes);
        Ok(self.store(&mut state, key, bytes, etag))
    }

    fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, BucketError> {
        let mut state = self.lock();
        let page = self.config.page_size.max(1);
        let keys: Vec<String> = state
            .objects
            .range(prefix.to_string()..)
            .map(|(key, _)| key.clone())
            .take_while(|key| key.starts_with(prefix))
            .collect();
        let mut out = Vec::with_capacity(keys.len());
        // Walk the listing one page per request, like a client does.
        for chunk in keys.chunks(page) {
            state.stats.lists += 1;
            for key in chunk {
                if let Some(object) = state.objects.get(key) {
                    out.push(Self::meta_of(key, object));
                }
            }
        }
        Ok(out)
    }

    fn put_large(
        &self,
        key: &str,
        bytes: &[u8],
        part_size: usize,
        cond: PutCond,
    ) -> Result<ObjectMeta, BucketError> {
        let part_size = part_size.max(self.min_part_size());
        let upload_id = {
            let mut state = self.lock();
            state.next_upload += 1;
            let id = format!("upload-{}", state.next_upload);
            state
                .uploads
                .insert(id.clone(), Upload { parts: Vec::new() });
            id
        };
        let mut parts: Vec<Vec<u8>> = Vec::new();
        for chunk in bytes.chunks(part_size) {
            parts.push(chunk.to_vec());
            let mut state = self.lock();
            state.stats.parts += 1;
            if let Some(upload) = state.uploads.get_mut(&upload_id) {
                upload.parts.push(chunk.to_vec());
            }
        }
        let etag = if parts.len() > 1 {
            multipart_etag(&parts)
        } else {
            single_part_etag(bytes)
        };
        let mut state = self.lock();
        // Completing (or refusing) the upload always closes it: nothing is left
        // sitting in a staging area.
        state.uploads.remove(&upload_id);
        self.evaluate(&mut state, key, &cond)?;
        state.stats.multipart_uploads += 1;
        Ok(self.store(&mut state, key, bytes, etag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_bucket_honours_create_only_and_if_match() {
        let bucket = MemoryBucket::forge("test-bucket");
        let meta = bucket
            .put("refs/heads/main", b"one", PutCond::CreateOnly)
            .expect("create-only on a fresh key");
        assert!(
            bucket
                .put("refs/heads/main", b"two", PutCond::CreateOnly)
                .is_err(),
            "create-only must not clobber"
        );
        let again = bucket.head("refs/heads/main").unwrap().unwrap();
        assert_eq!(again.etag, meta.etag);
        assert_eq!(
            bucket.get("refs/heads/main").unwrap().unwrap().bytes,
            b"one"
        );

        let stale = meta.etag.clone();
        bucket
            .put(
                "refs/heads/main",
                b"three",
                PutCond::IfMatch(again.etag.clone()),
            )
            .expect("matching etag lands");
        assert!(
            bucket
                .put("refs/heads/main", b"four", PutCond::IfMatch(stale))
                .is_err(),
            "a stale etag must be refused"
        );
        assert_eq!(
            bucket.get("refs/heads/main").unwrap().unwrap().bytes,
            b"three",
            "the refused write changed nothing"
        );
        assert_eq!(bucket.versions("refs/heads/main"), 2);
    }

    #[test]
    fn a_bucket_without_conditional_writes_says_so() {
        let bucket = MemoryBucket::without_conditional_writes("old-gateway");
        let err = bucket
            .put("refs/heads/main", b"one", PutCond::CreateOnly)
            .unwrap_err();
        assert_eq!(err.kind(), HostErrorKind::UnsupportedCas);
        assert!(err.is_conditional_unsupported());
        assert!(
            err.to_string().contains("refs/heads/main"),
            "the refusal names the key it refused: {err}"
        );
        assert!(!bucket.facts().unwrap().conditional_writes);
        assert!(!bucket.facts().unwrap().cas());
        assert!(MemoryBucket::forge("b").facts().unwrap().cas());
    }

    #[test]
    fn listings_are_sorted_paged_and_prefix_scoped() {
        let bucket = MemoryBucket::new(
            MemoryBucketConfig::default()
                .with_page_size(2)
                .with_bucket("paged"),
        );
        for key in [
            "gitiup/kv/attestation/b",
            "gitiup/kv/attestation/a",
            "gitiup/kv/attestation/c",
            "gitiup/kv/roster/d",
        ] {
            bucket.put(key, b"x", PutCond::Unconditional).unwrap();
        }
        let listed = bucket.list("gitiup/kv/attestation/").unwrap();
        let keys: Vec<&str> = listed.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "gitiup/kv/attestation/a",
                "gitiup/kv/attestation/b",
                "gitiup/kv/attestation/c"
            ]
        );
        assert!(
            bucket.stats().lists > 1,
            "three keys at page size 2 is more than one LIST: {}",
            bucket.stats().summary()
        );
        assert!(bucket.list("gitiup/kv/nothing/").unwrap().is_empty());
    }

    #[test]
    fn multipart_uploads_are_staged_and_counted() {
        let bucket = MemoryBucket::forge("multipart");
        let body = vec![7u8; 12 * 1024 * 1024];
        let meta = bucket
            .put_large(
                "gitiup/packs/big.pack",
                &body,
                8 * 1024 * 1024,
                PutCond::CreateOnly,
            )
            .expect("multipart write");
        assert!(
            meta.etag.contains('-'),
            "multipart etags carry a part count"
        );
        assert_eq!(bucket.stats().multipart_uploads, 1);
        assert_eq!(bucket.stats().parts, 2);
        assert_eq!(bucket.open_uploads(), 0, "the upload was closed out");
        assert_eq!(
            bucket.get("gitiup/packs/big.pack").unwrap().unwrap().bytes,
            body
        );
    }

    #[test]
    fn advice_names_the_gap() {
        let facts = BucketFacts {
            versioning: VersioningState::Disabled,
            object_lock: false,
            conditional_writes: false,
        };
        let advice = facts.advice();
        assert!(
            advice.iter().any(|a| a.contains("versioning")),
            "{advice:?}"
        );
        assert!(
            advice.iter().any(|a| a.contains("conditional")),
            "{advice:?}"
        );
        let healthy = BucketFacts {
            versioning: VersioningState::Enabled,
            object_lock: true,
            conditional_writes: true,
        };
        assert!(healthy.advice().is_empty());
        assert!(BucketFacts::unknown().advice().len() >= 2);
    }

    #[test]
    fn backoff_grows_and_caps() {
        let base = Duration::from_millis(10);
        let cap = Duration::from_millis(100);
        assert_eq!(backoff(0, base, cap), base);
        assert_eq!(backoff(1, base, cap), Duration::from_millis(20));
        assert_eq!(backoff(2, base, cap), Duration::from_millis(40));
        assert_eq!(backoff(30, base, cap), cap);
    }
}

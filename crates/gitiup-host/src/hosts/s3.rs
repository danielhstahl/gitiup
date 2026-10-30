//! Bucket-as-forge: one S3 (or MinIO) bucket is a complete remote.
//!
//! A bucket is not a forge, so nothing here pretends otherwise. Everything a
//! forge does is reduced to what a bucket *can* do — refs with compare-and-swap,
//! packs, content-addressed records — and everything else becomes owner-side
//! logic in `gitiup change` / `gitiup verify` rather than an API call.
//!
//! ```text
//! <root>/refs/<name>          small JSON document: { oid, updated_by, updated_at, schema }
//! <root>/packs/<oid>.pack     packfiles, content addressed (multipart above the threshold)
//! <root>/kv/<kind>/<hash>     change records, attestations, rosters, job records
//! <root>/host.json            the store manifest: schema, kind, bucket, root, created_at
//! ```
//!
//! `<root>` comes from [`RemoteConfig::root_prefix`], so `s3://gitiup-forge/my-repo`
//! with the default store prefix puts a branch at
//! `s3://gitiup-forge/my-repo/gitiup/refs/heads/main` — `aws s3 ls` and a
//! presigned URL see exactly the layout gitiup writes.
//!
//! # Concurrency, which is the whole trick
//!
//! Refs move with **compare-and-swap**, on S3 conditional writes:
//!
//! * [`Expect::Absent`] → `PUT` with `If-None-Match: *`
//! * [`Expect::Is`] → read the ref (which yields its etag), check the oid, then
//!   `PUT` with `If-Match: <etag>`
//! * [`Expect::Any`] → plain `PUT`, which gitiup never uses to gate a merge
//!
//! A 412 that a re-read explains becomes [`HostError::Conflict`] with both sides
//! filled in; a 412 that survives the re-read is retried with exponential backoff
//! ([`S3Options::cas_attempts`]), because that one is a lost race rather than a
//! moved ref. Two clones pushing at once therefore converge instead of losing a
//! ref.
//!
//! A bucket *without* conditional-write support is not silently downgraded: the
//! probe at [`S3Host::open`] sees it and reports `capabilities.cas = false`, and
//! every ref write that depends on CAS then refuses with
//! [`HostError::UnsupportedCas`] and a hint. That is the "no owner-side merges on
//! a dumb bucket" rule, in code.
//!
//! # What this host never does
//!
//! * **never deletes.** Removing a ref writes a tombstone document over it, and
//!   [`Bucket`] has no delete call at all. Object versioning is what makes
//!   overwriting safe, so connecting *requires* it and [`S3Host::advice`]
//!   recommends Object Lock retention.
//! * **never takes a static token.** Credentials come from the standard AWS
//!   chain — environment, shared profile (including `credential_process` and
//!   SSO), web identity/IRSA — via `aws-config`; see [`transport`]. A
//!   `gitiup.toml` that tries to hand the bucket a token is refused by
//!   [`S3Host::check_credentials`].
//! * **does not LIST on every read.** The ref advertisement is cached for a short
//!   TTL ([`S3Options::ref_cache_ttl`]) so repeated fetches are one lookup.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::blob::{BlobEntry, BlobStore, Namespace, Prefix};
use crate::capability::{AuthModel, Capabilities, Host, HostInfo, HostKind, implemented_by};
use crate::config::{RemoteConfig, RemoteScheme, one_line};
use crate::error::{Conflict, HostError, HostErrorKind, HostResult, NotFound};
use crate::oid::Oid;
use crate::pack::{Pack, PackFormat, PackRequest};
use crate::refs::{Actor, Expect, Ref, RefDeletion, RefName, RefQuery, RefStore, RefUpdate};
use crate::time::Timestamp;

pub mod bucket;
pub mod transport;

pub use bucket::{
    Bucket, BucketError, BucketFacts, BucketInfo, MemoryBucket, MemoryBucketConfig, Object,
    ObjectMeta, PutCond, SharedBucket, VersioningState,
};

/// Name of the store manifest object, under the store root.
pub const MANIFEST_NAME: &str = "host.json";

/// Ref documents live under `<root>/refs/`.
pub const REFS_DIR: &str = "refs";

/// Content-addressed records live under `<root>/kv/`.
pub const KV_DIR: &str = "kv";

/// Packfiles live under `<root>/packs/`.
pub const PACKS_DIR: &str = "packs";

/// Objects at least this big go up as a multipart upload.
pub const DEFAULT_MULTIPART_THRESHOLD_MIB: u64 = 8;

/// Multipart part size (S3's own minimum is 5 MiB).
pub const DEFAULT_PART_SIZE_MIB: u64 = 8;

/// How long the ref advertisement is reused.
pub const DEFAULT_REF_CACHE_TTL: Duration = Duration::from_secs(2);

/// Extra attempts a CAS write gets when a 412 is not explained by a moved ref.
pub const DEFAULT_CAS_ATTEMPTS: u32 = 4;

/// First backoff between those attempts.
pub const DEFAULT_CAS_BACKOFF: Duration = Duration::from_millis(20);

/// Ceiling for that backoff.
pub const DEFAULT_CAS_BACKOFF_CAP: Duration = Duration::from_secs(2);

/// How many ref documents are fetched in parallel when the listing is cold.
const REF_FETCH_LANES: usize = 8;

const MIB: usize = 1024 * 1024;

/// The document stored at every ref key.
///
/// The field names are the ones the design fixes (`oid`, `updated_by`,
/// `updated_at`, `schema`) so a ref can be read with
/// `aws s3 cp s3://…/refs/heads/main - | jq`. Unknown fields are ignored and a
/// *newer* `schema` is refused, so a document from a future gitiup is reported
/// rather than half-understood.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefDocument {
    /// Schema of this document (see [`crate::HOST_SCHEMA_VERSION`]).
    pub schema: u32,
    /// What the ref points at.
    pub oid: Oid,
    /// Who wrote it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Actor>,
    /// When it was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Timestamp>,
    /// Why it was written (audit trail, reflog-ish message).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// A deletion tombstone: the ref is gone, the object stays.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
    /// Who deleted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_by: Option<Actor>,
    /// When it was deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<Timestamp>,
}

impl RefDocument {
    /// A live ref document pointing at `oid`.
    pub fn new(oid: Oid) -> RefDocument {
        RefDocument {
            schema: crate::HOST_SCHEMA_VERSION,
            oid,
            updated_by: None,
            updated_at: None,
            message: None,
            deleted: false,
            deleted_by: None,
            deleted_at: None,
        }
    }

    /// A tombstone remembering `oid` as the value that was there.
    pub fn tombstone(oid: Oid, who: Option<Actor>) -> RefDocument {
        RefDocument {
            deleted: true,
            deleted_by: who,
            deleted_at: Some(Timestamp::now()),
            ..RefDocument::new(oid)
        }
    }

    /// Whether this document stands for a live ref.
    pub fn is_live(&self) -> bool {
        !self.deleted
    }

    /// The [`Ref`] a live document stands for.
    pub fn to_ref(&self, name: &RefName) -> Ref {
        Ref {
            name: name.clone(),
            oid: self.oid,
            updated_by: self.updated_by.clone(),
            updated_at: self.updated_at,
            schema: Some(self.schema),
        }
    }

    fn check_schema(&self, key: &str) -> HostResult<()> {
        if self.schema > crate::HOST_SCHEMA_VERSION_MAX {
            return Err(HostError::invalid(
                "ref document",
                format!(
                    "{key} was written by a newer gitiup (schema {})",
                    self.schema
                ),
            )
            .with_hint(format!(
                "upgrade gitiup; this build understands schema {}",
                crate::HOST_SCHEMA_VERSION
            )));
        }
        Ok(())
    }

    /// Canonical JSON bytes, newline-terminated so the object stays `jq`-friendly.
    pub fn encode(&self) -> HostResult<Vec<u8>> {
        let mut text = crate::config::canonical_json(self)?;
        text.push(b'\n');
        Ok(text)
    }

    /// Parse a ref object.
    pub fn decode(key: &str, bytes: &[u8]) -> HostResult<RefDocument> {
        let doc: RefDocument = serde_json::from_slice(bytes).map_err(|e| {
            HostError::invalid(
                "ref document",
                format!("{key} is not a ref document: {}", one_line(&e.to_string())),
            )
            .with_hint(
                "a ref object holds one JSON document: \
                 { \"oid\": \"<hex>\", \"updated_by\": …, \"updated_at\": …, \"schema\": 1 }",
            )
        })?;
        doc.check_schema(key)?;
        Ok(doc)
    }
}

/// The manifest [`S3Host::init`] writes once per store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostManifest {
    /// Schema of the documents this host writes.
    pub schema: u32,
    /// Always `s3`.
    pub kind: String,
    /// Bucket the store lives in.
    pub bucket: String,
    /// Key prefix of the store inside the bucket.
    pub root: String,
    /// Store prefix (`gitiup` by default).
    pub store_prefix: String,
    /// When the store was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
    /// Who created it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Implementation stamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implemented_by: Option<String>,
}

impl HostManifest {
    fn encode(&self) -> HostResult<Vec<u8>> {
        let mut text = crate::config::canonical_json(self)?;
        text.push(b'\n');
        Ok(text)
    }
}

/// What the operator says about conditional-write support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConditionalWrites {
    /// Ask the bucket (default).
    #[default]
    Auto,
    /// Trust that it works: a bucket that then refuses is an error, not a quiet
    /// downgrade.
    On,
    /// The bucket cannot do it: report `cas = false` without probing and refuse
    /// every CAS write.
    Off,
}

impl ConditionalWrites {
    /// Parse `auto|on|off` (plus the obvious synonyms).
    pub fn parse(text: &str) -> Result<ConditionalWrites, HostError> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "auto" | "probe" | "detect" => Ok(ConditionalWrites::Auto),
            "on" | "true" | "yes" | "enabled" | "required" => Ok(ConditionalWrites::On),
            "off" | "false" | "no" | "disabled" | "unsupported" => Ok(ConditionalWrites::Off),
            other => Err(HostError::invalid(
                "conditional-writes",
                format!("'{other}' is not a conditional-writes setting"),
            )
            .with_hint("expected auto, on or off")),
        }
    }

    /// Stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            ConditionalWrites::Auto => "auto",
            ConditionalWrites::On => "on",
            ConditionalWrites::Off => "off",
        }
    }
}

/// Knobs for the S3 host — every one of them a `[remote.options]` key in
/// `gitiup.toml` (or a query parameter on the remote URL).
///
/// The defaults describe a correctly configured S3 bucket; the explicit values
/// exist for MinIO, gateways and CI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Options {
    /// `region` — override the region the AWS chain resolved.
    pub region: Option<String>,
    /// `endpoint` — a MinIO or gateway URL, e.g. `http://127.0.0.1:9000`.
    pub endpoint: Option<String>,
    /// `profile` — shared-config profile, overriding `credentials-profile`.
    pub profile: Option<String>,
    /// `force-path-style` — required by most S3-compatible servers.
    pub force_path_style: bool,
    /// `require-versioning` — refuse unversioned buckets (default `true`: with
    /// no versioning, an overwrite destroys the previous object).
    pub require_versioning: bool,
    /// `conditional-writes` — `auto`, `on` or `off`.
    pub conditional_writes: ConditionalWrites,
    /// `multipart-threshold-mib` — objects at least this big go up as multipart.
    pub multipart_threshold: usize,
    /// `part-size-mib` — multipart part size (at least 5 MiB).
    pub part_size: usize,
    /// `ref-cache-ttl` — how long the ref advertisement is reused (`0s` turns the
    /// cache off).
    pub ref_cache_ttl: Duration,
    /// `cas-attempts` — extra attempts after a 412 a re-read did not explain.
    pub cas_attempts: u32,
    /// `cas-backoff` — first backoff between those attempts.
    pub cas_backoff: Duration,
    /// `cas-backoff-cap` — ceiling for that backoff.
    pub cas_backoff_cap: Duration,
    /// `anonymous` — the bucket serves **public reads**: no credential is sent, and no
    /// write is possible.
    ///
    /// This is a declaration by the operator, because a bucket that answers anonymous
    /// `GET`s and one that answers them today only because it is misconfigured look
    /// identical from here, and the difference decides whether a stranger may read the
    /// mirror or someone may overwrite it. Saying it turns the host read-only, makes
    /// [`Capabilities::auth`] honest about holding no credential, and stops the bucket
    /// being interrogated for facts an anonymous caller is not allowed to know
    /// (versioning, conditional writes) — those are bucket-admin questions, and refusing
    /// them says nothing about the objects (giti-g5c.5).
    ///
    /// The AWS transport refuses this declaration rather than pretending: an anonymous
    /// `GET` is an unsigned one, and the SDK signs everything it is given, so a read
    /// "from a public bucket" through it would really be a read as the owner. Public
    /// mirrors that need no credential are served over `git+https://` or plain HTTPS.
    pub anonymous: bool,
}

impl Default for S3Options {
    fn default() -> Self {
        S3Options {
            region: None,
            endpoint: None,
            profile: None,
            force_path_style: false,
            require_versioning: true,
            conditional_writes: ConditionalWrites::Auto,
            multipart_threshold: DEFAULT_MULTIPART_THRESHOLD_MIB as usize * MIB,
            part_size: DEFAULT_PART_SIZE_MIB as usize * MIB,
            ref_cache_ttl: DEFAULT_REF_CACHE_TTL,
            cas_attempts: DEFAULT_CAS_ATTEMPTS,
            cas_backoff: DEFAULT_CAS_BACKOFF,
            cas_backoff_cap: DEFAULT_CAS_BACKOFF_CAP,
            anonymous: false,
        }
    }
}

impl S3Options {
    /// Read the knobs out of a remote's `[remote.options]` table (overlaid on
    /// the URL query string).
    ///
    /// Unknown option keys are not an error — other hosts read the same table —
    /// but they come back as advice, so a typo surfaces in
    /// `gitiup remote doctor` instead of silently doing nothing.
    pub fn from_remote(remote: &RemoteConfig) -> HostResult<(S3Options, Vec<String>)> {
        let mut options = S3Options::default();
        let mut advice = Vec::new();
        for (key, value) in remote.effective_options() {
            let timeout = |value: &str| crate::config::parse_timeout(value);
            let known = match key.as_str() {
                "region" => {
                    options.region = Some(value.clone());
                    true
                }
                "endpoint" | "endpoint-url" => {
                    options.endpoint = Some(value.clone());
                    true
                }
                "profile" | "aws-profile" => {
                    options.profile = Some(value.clone());
                    true
                }
                "force-path-style" | "path-style" => {
                    options.force_path_style = parse_bool(&key, &value)?;
                    true
                }
                "require-versioning" => {
                    options.require_versioning = parse_bool(&key, &value)?;
                    true
                }
                "anonymous" | "public-read" => {
                    options.anonymous = parse_bool(&key, &value)?;
                    true
                }
                "conditional-writes" => {
                    options.conditional_writes = ConditionalWrites::parse(&value)?;
                    true
                }
                "multipart-threshold-mib" => {
                    options.multipart_threshold = parse_mib(&key, &value)?;
                    true
                }
                "part-size-mib" => {
                    options.part_size = parse_mib(&key, &value)?;
                    true
                }
                "ref-cache-ttl" => {
                    options.ref_cache_ttl = cache_timeout(&value)?;
                    true
                }
                "cas-attempts" => match value.trim().parse::<u32>() {
                    Ok(count) => {
                        options.cas_attempts = count;
                        true
                    }
                    Err(_) => {
                        return Err(HostError::invalid(
                            "cas-attempts",
                            format!("'{value}' is not a count"),
                        )
                        .with_hint("expected a small number of retries, e.g. 4"));
                    }
                },
                "cas-backoff" => {
                    options.cas_backoff = timeout(&value)?;
                    true
                }
                "cas-backoff-cap" => {
                    options.cas_backoff_cap = timeout(&value)?;
                    true
                }
                _ => false,
            };
            if !known {
                advice.push(format!(
                    "remote '{}' sets option '{key}', which the S3 host does not read",
                    remote.name
                ));
            }
        }
        if options.part_size < 5 * MIB {
            return Err(HostError::invalid(
                "part-size-mib",
                format!(
                    "{} MiB is below the 5 MiB multipart minimum",
                    options.part_size / MIB
                ),
            )
            .with_hint("S3 refuses multipart parts smaller than 5 MiB (except the last one)"));
        }
        if options.multipart_threshold < options.part_size {
            advice.push(format!(
                "multipart-threshold-mib ({} MiB) is below part-size-mib ({} MiB): large objects \
                 upload as a one-part multipart, which S3 allows but does not recommend",
                options.multipart_threshold / MIB,
                options.part_size / MIB
            ));
        }
        Ok((options, advice))
    }

    /// The multipart threshold in bytes, never below one part.
    pub fn threshold_bytes(&self) -> usize {
        self.multipart_threshold.max(self.part_size)
    }
}

/// `ref-cache-ttl`, including the spellings that mean "do not cache at all".
///
/// The general timeout parser rejects zero on purpose (a zero transport timeout
/// is a bug); for the advertisement cache zero is the documented way to opt out.
fn cache_timeout(raw: &str) -> HostResult<Duration> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if matches!(trimmed.as_str(), "off" | "no" | "none" | "never") {
        return Ok(Duration::ZERO);
    }
    let digits = trimmed
        .trim_end_matches("ms")
        .trim_end_matches(['s', 'm', 'h'])
        .trim();
    if digits == "0" {
        return Ok(Duration::ZERO);
    }
    crate::config::parse_timeout(raw)
}

fn parse_bool(key: &str, value: &str) -> HostResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(
            HostError::invalid(key, format!("'{other}' is not a boolean"))
                .with_hint("expected true or false"),
        ),
    }
}

fn parse_mib(key: &str, value: &str) -> HostResult<usize> {
    let number: u64 = value.trim().parse().map_err(|_| {
        HostError::invalid(key, format!("'{value}' is not a number of MiB"))
            .with_hint("sizes in these options are whole MiB, e.g. 8")
    })?;
    if number == 0 || number > 512 {
        return Err(HostError::invalid(
            key,
            format!("{number} MiB is outside the 1..=512 MiB range"),
        ));
    }
    Ok(number as usize * MIB)
}

/// Hit/miss counters for the ref advertisement cache — the numbers that make
/// "repeated fetches are cheap" observable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RefCacheStats {
    /// Listings served from the cache instead of a LIST plus one GET per ref.
    pub hits: usize,
    /// Listings that went to the bucket.
    pub misses: usize,
    /// Prefixes held right now.
    pub entries: usize,
}

/// A ref document plus the transport's identity for it.
#[derive(Debug, Clone)]
struct StoredRef {
    doc: RefDocument,
    etag: String,
}

impl StoredRef {
    /// The oid the ref advertises, `None` for a tombstone.
    fn advertised(&self) -> Option<Oid> {
        self.doc.is_live().then_some(self.doc.oid)
    }
}

#[derive(Debug, Default)]
struct RefCache {
    ttl: Duration,
    listings: BTreeMap<String, (Instant, Arc<Vec<Ref>>)>,
    hits: usize,
    misses: usize,
}

impl RefCache {
    fn new(ttl: Duration) -> RefCache {
        RefCache {
            ttl,
            ..RefCache::default()
        }
    }

    fn enabled(&self) -> bool {
        self.ttl > Duration::ZERO
    }

    fn fresh(&self, at: Instant) -> bool {
        self.enabled() && at.elapsed() < self.ttl
    }

    fn put_listing(&mut self, prefix: &str, refs: Arc<Vec<Ref>>) {
        if self.enabled() {
            self.listings
                .insert(prefix.to_string(), (Instant::now(), refs));
        }
    }

    fn get_listing(&mut self, prefix: &str) -> Option<Arc<Vec<Ref>>> {
        let (at, refs) = self.listings.get(prefix)?;
        if !self.fresh(*at) {
            return None;
        }
        self.hits += 1;
        Some(refs.clone())
    }

    fn invalidate(&mut self) {
        // Our own writes have to be visible immediately, and everything else is
        // cheaper to re-read than to reason about.
        //
        // Only listings are cached at all, on purpose: a listing is an
        // advertisement ("these are the refs I saw a moment ago") and every write
        // re-reads the ref it is about to replace, so a stale listing can never
        // turn into a lost update.
        self.listings.clear();
    }
}

/// Why a CAS write did not land.
enum CasFailure {
    /// The expectation did not hold: report it, with both sides.
    Conflict(HostError),
    /// Transport trouble that has nothing to do with CAS.
    Fatal(HostError),
}

impl From<HostError> for CasFailure {
    fn from(err: HostError) -> CasFailure {
        CasFailure::Fatal(err)
    }
}

impl From<CasFailure> for HostError {
    fn from(failure: CasFailure) -> HostError {
        match failure {
            CasFailure::Conflict(err) | CasFailure::Fatal(err) => err,
        }
    }
}

/// An S3 bucket used as the forge.
///
/// Cloning is cheap (an `Arc`) and the type is `Send + Sync`, so a verification
/// run can read several buckets from threads and hand one around as
/// `Arc<dyn Host>`. Build it with [`S3Host::open`], [`S3Host::init`] or
/// [`S3Host::from_remote`].
#[derive(Clone)]
pub struct S3Host {
    inner: Arc<Inner>,
}

struct Inner {
    bucket: SharedBucket,
    remote: RemoteConfig,
    options: S3Options,
    facts: BucketFacts,
    capabilities: Capabilities,
    advice: Vec<String>,
    cache: Mutex<RefCache>,
    /// Namespaces seen in `kv/`, so looking a blob up is a few HEADs instead of a
    /// listing of the whole store.
    namespaces: Mutex<BTreeSet<String>>,
}

impl fmt::Debug for S3Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Host")
            .field("remote", &self.inner.remote.name)
            .field("root", &self.root())
            .field("capabilities", &self.inner.capabilities)
            .finish_non_exhaustive()
    }
}

/// Should connecting interrogate the bucket?
enum Probe {
    Ask,
    Skip,
}

fn capabilities_for(facts: &BucketFacts, anonymous: bool) -> Capabilities {
    Capabilities {
        // No conditional writes means `cas = false`, and every write that gates a
        // merge refuses there. That is the design rule, not a limitation to work
        // around: a lost update on a merge gate is a lost merge.
        cas: facts.cas(),
        immutable: facts.versioning.protects_history(),
        // S3 has no multi-object transaction. `RefStore::update_refs_cas`'s
        // default implementation applies updates in order and rolls back on a
        // failure, so callers have to be told it is not atomic.
        atomic_multi_write: false,
        // "Which credential does this handle hold" is a question a caller branches on,
        // and the answer for a public-read bucket is: none. Saying `cloud-role` there
        // would promise an identity the transport never sends.
        auth: if anonymous {
            AuthModel::Anonymous
        } else {
            AuthModel::CloudRole
        },
    }
}

fn check_scheme(remote: &RemoteConfig) -> HostResult<()> {
    if remote.scheme() == RemoteScheme::S3 {
        return Ok(());
    }
    Err(HostError::SchemeUnknown(Box::new(
        crate::error::SchemeUnknown {
            scheme: remote.scheme().as_str().to_string(),
            supported: vec![RemoteScheme::S3.as_str().to_string()],
            hint: Some(format!(
                "remote '{}' points at {}: the S3 host only serves s3:// remotes",
                remote.name,
                remote.redacted_url()
            )),
        },
    )))
}

fn versioning_error(remote: &RemoteConfig, facts: &BucketFacts) -> HostError {
    HostError::unsupported(
        "immutable",
        format!(
            "the bucket for '{}' is not versioned (versioning: {}), so overwriting a ref or a \
             record destroys the previous object",
            remote.name, facts.versioning
        ),
    )
    .with_hint(
        "enable object versioning (aws s3api put-bucket-versioning --bucket <bucket> \
         --versioning-configuration Status=Enabled), or set require-versioning = \"false\" in \
         [remote.options] to accept that records are not immutable",
    )
}

fn conflict(name: &RefName, expected: Option<Oid>, found: Option<Oid>) -> HostError {
    HostError::conflict(name.as_str(), expected, found)
        .with_hint("the ref moved under us: re-read it, rebuild the update and retry")
}

/// A CAS write against a ref key: move it, or tombstone it.
enum WriteTarget {
    Move(RefUpdate),
    Tombstone {
        oid: Oid,
        actor: Option<Actor>,
        /// The etag of the document the caller saw, so the tombstone cannot
        /// clobber a ref that moved in between.
        if_match: Option<String>,
    },
}

impl WriteTarget {
    fn expect(&self) -> Expect {
        match self {
            WriteTarget::Move(update) => update.expect,
            // A tombstone replaces the document that is there; the caller's
            // expectation was already checked against a fresh read.
            WriteTarget::Tombstone { .. } => Expect::Any,
        }
    }

    /// The condition this write must carry, for a move target that does not need
    /// the current document read first.
    fn condition(&self) -> Option<PutCond> {
        match self {
            WriteTarget::Move(_) => None,
            WriteTarget::Tombstone {
                if_match: Some(etag),
                ..
            } => Some(PutCond::IfMatch(etag.clone())),
            WriteTarget::Tombstone { if_match: None, .. } => Some(PutCond::Unconditional),
        }
    }

    fn encode(&self) -> HostResult<Vec<u8>> {
        match self {
            WriteTarget::Move(update) => {
                let mut doc = RefDocument::new(update.new);
                doc.updated_by = update.actor.clone().or_else(|| Some(Actor::from_env()));
                doc.updated_at = Some(Timestamp::now());
                doc.message = update.message.clone();
                doc.encode()
            }
            WriteTarget::Tombstone { oid, actor, .. } => {
                RefDocument::tombstone(*oid, actor.clone().or_else(|| Some(Actor::from_env())))
                    .encode()
            }
        }
    }
}

/// The namespaces the well-known record kinds use, so the first lookup of a blob
/// is a handful of HEADs instead of a full listing.
fn known_namespaces() -> BTreeSet<String> {
    [
        Namespace::CHANGE,
        Namespace::ATTESTATION,
        Namespace::ROSTER,
        Namespace::JOB,
        Namespace::POLICY,
        Namespace::RECORD,
    ]
    .into_iter()
    .map(|namespace| namespace.as_str().to_string())
    .collect()
}

impl S3Host {
    /// Open an existing bucket-as-forge store: probe the bucket, require
    /// versioning unless that was turned off, and insist on the store manifest.
    pub fn open(bucket: SharedBucket, remote: &RemoteConfig) -> HostResult<S3Host> {
        let host = Self::connect(bucket, remote, Probe::Ask)?;
        match host.read_manifest()? {
            None => Err(
                HostError::not_found("host manifest", host.manifest_key()).with_hint(format!(
                    "{} is not initialised as a gitiup store; initialise it with S3Host::init",
                    remote.redacted_url()
                )),
            ),
            Some(manifest) => {
                if manifest.schema > crate::HOST_SCHEMA_VERSION_MAX {
                    return Err(HostError::invalid(
                        MANIFEST_NAME,
                        format!(
                            "{} was written by a newer gitiup (schema {})",
                            host.manifest_key(),
                            manifest.schema
                        ),
                    )
                    .with_hint(format!(
                        "upgrade gitiup; this build understands schema {}",
                        crate::HOST_SCHEMA_VERSION
                    )));
                }
                if manifest.kind != HostKind::S3.as_str() {
                    return Err(HostError::invalid(
                        MANIFEST_NAME,
                        format!(
                            "{} declares kind '{}', expected '{}'",
                            host.manifest_key(),
                            manifest.kind,
                            HostKind::S3.as_str()
                        ),
                    ));
                }
                Ok(host)
            }
        }
    }

    /// Create the store in a bucket: the manifest goes in with a create-only
    /// write, so two people initialising at once cannot clobber each other.
    pub fn init(bucket: SharedBucket, remote: &RemoteConfig) -> HostResult<S3Host> {
        let host = Self::connect(bucket.clone(), remote, Probe::Ask)?;
        if let Some(manifest) = host.read_manifest()? {
            return Err(HostError::invalid(
                MANIFEST_NAME,
                format!(
                    "{} already exists (created {})",
                    host.manifest_key(),
                    manifest
                        .created_at
                        .map(|at| at.to_string())
                        .unwrap_or_else(|| "earlier".to_string())
                ),
            )
            .with_hint("open it with S3Host::open instead of initialising it again"));
        }
        host.write_manifest_create()?;
        Ok(host)
    }

    /// Open the store, creating it when the bucket holds no store yet.
    pub fn open_or_init(bucket: SharedBucket, remote: &RemoteConfig) -> HostResult<S3Host> {
        let host = Self::connect(bucket, remote, Probe::Ask)?;
        if host.read_manifest()?.is_some() {
            return Ok(host);
        }
        let key = host.manifest_key();
        let bytes = host.manifest_bytes()?;
        let cond = if host.inner.facts.conditional_writes {
            PutCond::CreateOnly
        } else {
            PutCond::Unconditional
        };
        match host.write_raw(&key, &bytes, cond) {
            Ok(_) => Ok(host),
            // A race is fine here: whoever won, the store is initialised, and the
            // manifest now in the bucket is the one both of us would have written.
            Err(err) if err.is_precondition_failed() => Ok(host),
            Err(err) => Err(host.transport_error(&key, err)),
        }
    }

    /// A host that trusts the bucket it was handed and asks it nothing: no
    /// versioning requirement, no manifest check, and — because nothing was
    /// probed — no immutability promise either. For tests and dry runs.
    pub fn detached(bucket: SharedBucket, remote: &RemoteConfig) -> HostResult<S3Host> {
        Self::connect(bucket, remote, Probe::Skip)
    }

    /// Open the `s3://` remote named in a `gitiup.toml`, over a transport built
    /// from the standard AWS credential chain.
    ///
    /// Without the `s3` feature compiled in there is no S3 transport in the
    /// binary, and the error says exactly that.
    pub fn from_remote(remote: &RemoteConfig) -> HostResult<S3Host> {
        check_scheme(remote)?;
        let bucket = transport::connect(remote)?;
        S3Host::open(bucket, remote)
    }

    /// Open the `s3://` remote named in a `gitiup.toml`, writing the store
    /// manifest if the bucket is otherwise empty.
    pub fn open_or_init_remote(remote: &RemoteConfig) -> HostResult<S3Host> {
        check_scheme(remote)?;
        let bucket = transport::connect(remote)?;
        S3Host::open_or_init(bucket, remote)
    }

    fn connect(bucket: SharedBucket, remote: &RemoteConfig, probe: Probe) -> HostResult<S3Host> {
        check_scheme(remote)?;
        let (mut options, mut advice) = S3Options::from_remote(remote)?;
        let mut facts = match probe {
            Probe::Skip => BucketFacts::unknown(),
            Probe::Ask => bucket.facts().map_err(HostError::from)?,
        };
        if options.conditional_writes == ConditionalWrites::Off {
            facts.conditional_writes = false;
        }
        if options.require_versioning && !facts.versioning.protects_history() {
            return Err(versioning_error(remote, &facts));
        }
        // `conditional-writes = on` is a promise; a bucket that breaks it is an
        // error rather than a quiet downgrade.
        if options.conditional_writes == ConditionalWrites::On && !facts.cas() {
            return Err(HostError::unsupported(
                "cas",
                format!(
                    "remote '{}' promises conditional writes but {} does not answer them",
                    remote.name,
                    bucket.info()
                ),
            )
            .with_hint(
                "drop conditional-writes = \"on\" from [remote.options] to accept a bucket \
                 where gitiup will not gate merges",
            ));
        }
        if options.ref_cache_ttl == Duration::ZERO {
            advice.push("ref-cache-ttl = 0s: every ref read goes back to the bucket".to_string());
        }
        if options.anonymous {
            advice.push(
                "this remote is declared anonymous (public-read): no credential is sent, so \
                 every write is refused here before it reaches the bucket — which is what a \
                 public mirror of a private repository is for"
                    .to_string(),
            );
            // The two probe questions a public bucket cannot answer: versioning and the
            // conditional-write probe are bucket-admin calls an anonymous caller is
            // refused, and being refused them says nothing about the objects. Without
            // this, a perfectly served public bucket would fail to open.
            options.require_versioning = false;
            options.conditional_writes = ConditionalWrites::Off;
        }
        advice.extend(facts.advice());
        options.cas_attempts = options.cas_attempts.min(16);
        let capabilities = capabilities_for(&facts, options.anonymous);
        Ok(S3Host {
            inner: Arc::new(Inner {
                bucket,
                remote: remote.clone(),
                cache: Mutex::new(RefCache::new(options.ref_cache_ttl)),
                namespaces: Mutex::new(known_namespaces()),
                advice,
                capabilities,
                facts,
                options,
            }),
        })
    }

    // -- identity and diagnostics -----------------------------------------

    /// The remote this host was built from.
    pub fn remote(&self) -> &RemoteConfig {
        &self.inner.remote
    }

    /// What the probe found out about the bucket.
    pub fn facts(&self) -> BucketFacts {
        self.inner.facts
    }

    /// Where the bucket is and how we authenticated — never a secret.
    pub fn bucket_info(&self) -> BucketInfo {
        self.inner.bucket.info()
    }

    /// What `gitiup remote doctor` should say about this bucket.
    pub fn advice(&self) -> &[String] {
        &self.inner.advice
    }

    /// The store root inside the bucket (`<url path>/<store-prefix>`).
    pub fn root(&self) -> String {
        self.inner.remote.root_prefix()
    }

    /// Object key of the store manifest.
    pub fn manifest_key(&self) -> String {
        format!("{}/{}", self.root(), MANIFEST_NAME)
    }

    /// Object key of a ref document (`<root>/refs/<name>`).
    pub fn ref_key(&self, name: &RefName) -> String {
        self.inner.remote.ref_key(name)
    }

    /// Object key of a content-addressed record (`<root>/kv/<kind>/<hash>`).
    pub fn kv_key(&self, namespace: &Namespace, oid: &Oid) -> String {
        self.inner.remote.kv_key(namespace, oid)
    }

    /// Object key of a pack (`<root>/packs/<oid>.pack`).
    pub fn pack_key(&self, oid: &Oid) -> String {
        self.inner.remote.pack_key(oid)
    }

    /// Options this host is running with.
    pub fn options(&self) -> &S3Options {
        &self.inner.options
    }

    /// The store manifest, as stored.
    pub fn manifest(&self) -> HostResult<Option<HostManifest>> {
        self.read_manifest()
    }

    /// The ref advertisement cache counters — the evidence that repeated fetches
    /// are cheap.
    pub fn ref_cache_stats(&self) -> RefCacheStats {
        let cache = self.lock_cache();
        RefCacheStats {
            hits: cache.hits,
            misses: cache.misses,
            entries: cache.listings.len(),
        }
    }

    /// Forget every cached ref and listing (what `gitiup fetch --refresh` does).
    pub fn flush_ref_cache(&self) {
        self.lock_cache().invalidate();
    }

    /// How many objects the store holds. Deleting a ref never lowers this,
    /// because nothing is deleted — refs are tombstoned.
    pub fn object_count(&self) -> HostResult<usize> {
        Ok(self.listing(&format!("{}/", self.root()))?.len())
    }

    /// Raw bytes of an object in the store, for `gitiup remote show` and tests.
    pub fn read_object(&self, key: &str) -> HostResult<Option<Vec<u8>>> {
        Ok(self.read(key)?.map(|object| object.bytes))
    }

    /// The document stored for `name`, tombstones included.
    pub fn ref_document(&self, name: &RefName) -> HostResult<Option<RefDocument>> {
        Ok(self.read_ref(name)?.map(|stored| stored.doc))
    }

    /// Refuse a `gitiup.toml` that hands the bucket a token.
    ///
    /// The bucket is authenticated by the AWS chain (env, shared profile, SSO,
    /// web identity); a token in the config is both useless here and a leak
    /// waiting to happen, so the problem is raised before anything is sent — and
    /// checked against the *profile*, not only against whether the environment
    /// happens to have the variable set today.
    pub fn check_credentials(
        config: &crate::config::Config,
        remote: &RemoteConfig,
    ) -> HostResult<()> {
        check_scheme(remote)?;
        let profile = config.credential_profile(remote);
        let names_a_token =
            profile.is_some_and(|p| p.token_env.is_some() || p.auth == Some(AuthModel::Token));
        if names_a_token {
            return Err(Self::token_refused(remote, "names a token"));
        }
        let credentials = config.credentials_for(remote)?;
        if credentials.has_token() || credentials.auth == AuthModel::Token {
            return Err(Self::token_refused(
                remote,
                &format!("resolves to one ({})", credentials.source),
            ));
        }
        Ok(())
    }

    fn token_refused(remote: &RemoteConfig, why: &str) -> HostError {
        HostError::unsupported(
            "token-credentials",
            format!(
                "the credentials profile for remote '{}' ({}) but an s3 remote is authenticated \
                 by the AWS credential chain",
                remote.name, why
            ),
        )
        .with_hint(
            "drop token-env from the credentials profile and use auth = \"cloud-role\": AWS \
             credentials come from the environment, a shared-config profile, SSO or a web \
             identity (IRSA) — never from gitiup.toml",
        )
    }

    // -- plumbing ---------------------------------------------------------

    fn lock_cache(&self) -> MutexGuard<'_, RefCache> {
        self.inner
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn note_write(&self) {
        self.lock_cache().invalidate();
    }

    fn note_namespace(&self, namespace: &Namespace) {
        let mut known = self
            .inner
            .namespaces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        known.insert(namespace.as_str().to_string());
    }

    fn known_namespaces(&self) -> Vec<Namespace> {
        let held = self
            .inner
            .namespaces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        held.iter()
            .filter_map(|name| Namespace::new(name.clone()).ok())
            .collect()
    }

    fn read(&self, key: &str) -> HostResult<Option<Object>> {
        self.inner.bucket.get(key).map_err(HostError::from)
    }

    fn head(&self, key: &str) -> HostResult<Option<ObjectMeta>> {
        self.inner.bucket.head(key).map_err(HostError::from)
    }

    fn listing(&self, prefix: &str) -> HostResult<Vec<ObjectMeta>> {
        self.inner.bucket.list(prefix).map_err(HostError::from)
    }

    /// Record the manifest, refusing to clobber an existing store.
    ///
    /// On a bucket with no conditional writes there is nothing to compare-and-set
    /// with, so the absence check we just did is the only guarantee available —
    /// which is exactly why a store's bootstrap is its own operation and not
    /// something the ref protocol has to protect.
    fn write_manifest_create(&self) -> HostResult<()> {
        let key = self.manifest_key();
        let bytes = self.manifest_bytes()?;
        let cond = if self.inner.facts.conditional_writes {
            PutCond::CreateOnly
        } else {
            PutCond::Unconditional
        };
        match self.write_raw(&key, &bytes, cond) {
            Ok(_) => Ok(()),
            Err(err) if err.is_precondition_failed() => Err(HostError::invalid(
                MANIFEST_NAME,
                format!("{} already exists", key),
            )
            .with_hint("somebody else initialised this bucket first; open it with S3Host::open")),
            Err(err) => Err(self.transport_error(&key, err)),
        }
    }

    fn manifest_bytes(&self) -> HostResult<Vec<u8>> {
        HostManifest {
            schema: crate::HOST_SCHEMA_VERSION,
            kind: HostKind::S3.as_str().to_string(),
            bucket: self.bucket_info().bucket,
            root: self.root(),
            store_prefix: self.inner.remote.store_prefix.clone(),
            created_at: Some(Timestamp::now()),
            created_by: Some(Actor::from_env().to_string()),
            implemented_by: Some(implemented_by("s3")),
        }
        .encode()
    }

    /// Write an object, choosing multipart once it is big enough to want it, and
    /// handing back the raw transport error so a CAS loop can tell a 412 from
    /// real trouble.
    fn write_raw(&self, key: &str, bytes: &[u8], cond: PutCond) -> Result<ObjectMeta, BucketError> {
        let attempt = if bytes.len() >= self.inner.options.threshold_bytes() {
            let part = self.inner.options.part_size;
            self.inner.bucket.put_large(key, bytes, part, cond.clone())
        } else {
            self.inner.bucket.put(key, bytes, cond.clone())
        };
        match attempt {
            Ok(meta) => Ok(meta),
            // A gateway with no multipart at all still has to take the object,
            // but dropping a condition would silently break CAS — so fall back to
            // a plain PUT only when nothing was promised.
            Err(err)
                if err
                    .unsupported_feature()
                    .is_some_and(|feature| feature.starts_with("multipart")) =>
            {
                if cond.is_conditional() {
                    Err(BucketError::Unsupported {
                        feature: "multipart-with-conditions".to_string(),
                        message: format!(
                            "{key}: this endpoint cannot write a {} byte object ({}) as a \
                             multipart upload, and the write needs the condition to hold",
                            bytes.len(),
                            cond.describe()
                        ),
                    })
                } else {
                    self.inner.bucket.put(key, bytes, PutCond::Unconditional)
                }
            }
            Err(err) => Err(err),
        }
    }

    fn transport_error(&self, key: &str, err: BucketError) -> HostError {
        let mapped = HostError::from(err);
        if mapped.kind() == HostErrorKind::UnsupportedCas {
            return mapped.with_hint(format!(
                "the bucket behind {} cannot do this write; `gitiup remote doctor` lists what it \
                 does support (last key: {key})",
                self.inner.remote.redacted_url()
            ));
        }
        mapped
    }

    /// Read a ref document plus its etag, always from the bucket: a CAS
    /// precondition must never be checked against a cached value.
    fn read_ref(&self, name: &RefName) -> HostResult<Option<StoredRef>> {
        let key = self.ref_key(name);
        match self.read(&key)? {
            None => Ok(None),
            Some(object) => {
                let doc = RefDocument::decode(&key, &object.bytes)?;
                Ok(Some(StoredRef {
                    doc,
                    etag: object.etag,
                }))
            }
        }
    }

    /// Turn an [`Expect`] into the condition to write with, checking the current
    /// document first so a refusal can name both sides.
    ///
    /// `Ok(None)` means "the expectation holds and the key is free";
    /// `Ok(Some(_))` hands back the etag to `If-Match` — including for a
    /// tombstone, which is what makes delete-then-recreate safe.
    fn condition_for(
        &self,
        name: &RefName,
        expect: Expect,
    ) -> Result<Option<StoredRef>, CasFailure> {
        match expect {
            Expect::Any => Ok(None),
            Expect::Absent => match self.read_ref(name).map_err(CasFailure::Fatal)? {
                Some(stored) if stored.doc.is_live() => Err(CasFailure::Conflict(conflict(
                    name,
                    None,
                    stored.advertised(),
                ))),
                Some(stored) => Ok(Some(stored)),
                None => Ok(None),
            },
            Expect::Is(previous) => match self.read_ref(name).map_err(CasFailure::Fatal)? {
                None => Err(CasFailure::Conflict(conflict(name, Some(previous), None))),
                Some(stored) if stored.advertised() != Some(previous) => Err(CasFailure::Conflict(
                    conflict(name, Some(previous), stored.advertised()),
                )),
                Some(stored) => Ok(Some(stored)),
            },
        }
    }

    /// One CAS write, retried with backoff while the failures are unexplained 412s.
    fn cas_write(&self, name: &RefName, target: &WriteTarget) -> HostResult<()> {
        if target.expect() != Expect::Any {
            self.require_cas(name)?;
        }
        let key = self.ref_key(name);
        let body = target.encode()?;
        let mut attempt: u32 = 0;
        loop {
            let cond = match target.condition() {
                Some(cond) => cond,
                None => match self.condition_for(name, target.expect())? {
                    Some(stored) => PutCond::IfMatch(stored.etag.clone()),
                    None if target.expect() == Expect::Any => PutCond::Unconditional,
                    None => PutCond::CreateOnly,
                },
            };
            match self.write_raw(&key, &body, cond) {
                Ok(_) => return Ok(()),
                Err(BucketError::PreconditionFailed { condition, .. }) => {
                    // Either the ref moved — the re-read at the top of the next
                    // pass sees it and turns the failure into a Conflict with both
                    // sides — or the bucket flinched. Back off and retry until the
                    // budget is gone.
                    if attempt >= self.inner.options.cas_attempts {
                        return Err(self.gave_up(name, attempt + 1, &condition));
                    }
                    std::thread::sleep(bucket::backoff(
                        attempt,
                        self.inner.options.cas_backoff,
                        self.inner.options.cas_backoff_cap,
                    ));
                    attempt += 1;
                }
                Err(err) if err.is_conditional_unsupported() => {
                    return Err(self.cas_refused(&err));
                }
                Err(err) => return Err(self.transport_error(&key, err)),
            }
        }
    }

    fn gave_up(&self, name: &RefName, attempts: u32, condition: &str) -> HostError {
        let found = self
            .read_ref(name)
            .ok()
            .flatten()
            .and_then(|stored| stored.advertised());
        HostError::Conflict(Box::new(Conflict {
            name: name.as_str().to_string(),
            expected: None,
            found,
            actor: None,
            hint: Some(format!(
                "gave up after {attempts} attempts: {} kept refusing the write ({condition}) \
                 without the ref moving",
                self.inner.remote.redacted_url()
            )),
        }))
    }

    fn cas_refused(&self, err: &BucketError) -> HostError {
        HostError::unsupported(
            "cas",
            format!(
                "{} refuses conditional writes: {err}",
                self.inner.remote.redacted_url()
            ),
        )
        .with_hint(
            "gitiup will not gate a merge on a bucket that cannot compare-and-swap; enable \
             conditional writes, or record the fact with conditional-writes = \"off\" in \
             [remote.options]",
        )
    }

    fn require_cas(&self, name: &RefName) -> HostResult<()> {
        if self.inner.capabilities.cas {
            return Ok(());
        }
        Err(HostError::unsupported(
            "cas",
            format!(
                "cannot update {} on {} without compare-and-swap",
                name,
                self.inner.remote.redacted_url()
            ),
        )
        .with_hint(
            "this bucket has no conditional writes (If-Match / If-None-Match), so a ref update \
             here could silently lose another writer's ref; enable conditional writes, use a \
             git-backed host, or write unconditionally on purpose with Expect::Any",
        ))
    }

    // -- kv layout ---------------------------------------------------------

    fn kv_prefix(&self) -> String {
        format!("{}/", self.inner.remote.kv_root())
    }

    /// Split a `kv/` key into `(namespace, digest-hex)`, ignoring anything that is
    /// not ours — a foreign object in a shared bucket is nobody's business.
    fn parse_kv_key(&self, key: &str) -> Option<(Namespace, String)> {
        let rest = key.strip_prefix(&self.kv_prefix())?;
        let (namespace, digest) = rest.split_once('/')?;
        if digest.is_empty() || digest.contains('/') {
            return None;
        }
        let namespace = Namespace::new(namespace).ok()?;
        Oid::from_hex(digest).ok()?;
        Some((namespace, digest.to_ascii_lowercase()))
    }

    /// Where a blob lives: search the namespaces we know, then fall back to a
    /// `kv/` listing.
    fn find_kv(&self, oid: &Oid) -> HostResult<Option<(Namespace, String)>> {
        let hex = oid.hex();
        for namespace in self.known_namespaces() {
            let key = self.kv_key(&namespace, oid);
            if self.head(&key)?.is_some() {
                return Ok(Some((namespace, key)));
            }
        }
        let prefix = self.kv_prefix();
        for meta in self.listing(&prefix)? {
            if !meta.key.ends_with(&hex) {
                continue;
            }
            if let Some((namespace, digest)) = self.parse_kv_key(&meta.key)
                && digest == hex
            {
                return Ok(Some((namespace, meta.key)));
            }
        }
        Ok(None)
    }

    fn read_manifest(&self) -> HostResult<Option<HostManifest>> {
        let key = self.manifest_key();
        let Some(object) = self.read(&key)? else {
            return Ok(None);
        };
        let manifest = serde_json::from_slice(&object.bytes).map_err(|e| {
            HostError::invalid(
                MANIFEST_NAME,
                format!("{key} is not a host manifest: {}", one_line(&e.to_string())),
            )
        })?;
        Ok(Some(manifest))
    }
}

// ---------------------------------------------------------------------------
// The traits
// ---------------------------------------------------------------------------

impl S3Host {
    /// Object prefix a ref listing starts at.
    ///
    /// A prefix always ends at a component boundary, so `refs/changes` never
    /// matches `refs/changesets/…`.
    fn ref_object_prefix(&self, ref_prefix: Option<&str>) -> String {
        let root = format!("{}/{}/", self.root(), REFS_DIR);
        let Some(prefix) = ref_prefix.map(str::trim).filter(|p| !p.is_empty()) else {
            return root;
        };
        let trimmed = prefix.trim_matches('/');
        let tail = trimmed.strip_prefix("refs/").unwrap_or(trimmed);
        if tail.is_empty() {
            root
        } else {
            format!("{root}{tail}/")
        }
    }

    /// The ref name a ref key stands for, tolerating both the documented
    /// `<root>/refs/heads/main` shape and `<root>/refs/refs/heads/main`, which a
    /// hand-written object could have.
    fn ref_name_for_key(&self, key: &str) -> Option<RefName> {
        let root = format!("{}/{}/", self.root(), REFS_DIR);
        let tail = key.strip_prefix(&root)?;
        if tail.is_empty() || tail.ends_with('/') {
            return None;
        }
        if tail == crate::refs::ns::HEAD {
            return Some(RefName::head());
        }
        let text = if tail.starts_with("refs/") {
            tail.to_string()
        } else {
            format!("refs/{tail}")
        };
        RefName::new(text).ok()
    }

    /// Read one ref object and turn it into a [`Ref`], caching it on the way.
    ///
    /// `Ok(None)` covers both "the object vanished between LIST and GET" and "it
    /// is a tombstone"; either way the ref is not advertised.
    fn ref_from_key(&self, key: &str) -> HostResult<Option<Ref>> {
        let name = self.ref_name_for_key(key).ok_or_else(|| {
            HostError::invalid(
                "ref key",
                format!("{key} is not a ref object of this store"),
            )
        })?;
        let Some(object) = self.read(key)? else {
            return Ok(None);
        };
        let doc = RefDocument::decode(key, &object.bytes)?;
        if !doc.is_live() {
            return Ok(None);
        }
        Ok(Some(doc.to_ref(&name)))
    }

    /// Fetch a whole listing's ref documents, a few lanes at a time.
    ///
    /// LIST gives keys but not values, so a cold `list_refs` costs one LIST plus
    /// one GET per ref — which is precisely why the result is cached for
    /// [`S3Options::ref_cache_ttl`].
    fn refs_from_listing(&self, metas: &[ObjectMeta]) -> HostResult<Vec<Ref>> {
        if metas.is_empty() {
            return Ok(Vec::new());
        }
        let lanes = REF_FETCH_LANES.min(metas.len());
        let mut pairs: Vec<(usize, HostResult<Option<Ref>>)> = Vec::with_capacity(metas.len());
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(lanes);
            for lane in 0..lanes {
                let host = self.clone();
                let work: Vec<(usize, String)> = metas
                    .iter()
                    .enumerate()
                    .skip(lane)
                    .step_by(lanes)
                    .map(|(idx, meta)| (idx, meta.key.clone()))
                    .collect();
                handles.push(scope.spawn(move || {
                    work.into_iter()
                        .map(|(idx, key)| (idx, host.ref_from_key(&key)))
                        .collect::<Vec<_>>()
                }));
            }
            for handle in handles {
                match handle.join() {
                    Ok(done) => pairs.extend(done),
                    Err(_) => pairs.push((
                        usize::MAX,
                        Err(HostError::unreachable("a ref reader panicked")),
                    )),
                }
            }
        });
        pairs.sort_by_key(|(idx, _)| *idx);
        let mut refs = Vec::with_capacity(metas.len());
        for (_, result) in pairs {
            if let Some(reference) = result? {
                refs.push(reference);
            }
        }
        refs.sort_by(|a, b| a.name.cmp(&b.name));
        refs.dedup_by(|a, b| a.name == b.name);
        Ok(refs)
    }
}

impl RefStore for S3Host {
    fn list_refs(&self, query: &RefQuery) -> HostResult<Vec<Ref>> {
        let cache_key = match &query.prefix {
            Some(prefix) => prefix.trim_matches('/').to_string(),
            None => "*".to_string(),
        };
        let cached = self.lock_cache().get_listing(&cache_key);
        let mut refs = match cached {
            Some(cached) => (*cached).clone(),
            None => {
                let metas = self.listing(&self.ref_object_prefix(query.prefix.as_deref()))?;
                let fresh = self.refs_from_listing(&metas)?;
                self.lock_cache()
                    .put_listing(&cache_key, Arc::new(fresh.clone()));
                self.lock_cache().misses += 1;
                fresh
            }
        };
        refs.retain(|reference| query.matches(&reference.name));
        if let Some(limit) = query.limit {
            refs.truncate(limit);
        }
        Ok(refs)
    }

    /// A point lookup is one fresh GET: a caller asking "where is this ref now?"
    /// must never be answered from the advertisement cache, whose whole purpose is
    /// to make *listings* cheap.
    fn get_ref(&self, name: &RefName) -> HostResult<Option<Ref>> {
        let Some(stored) = self.read_ref(name)? else {
            return Ok(None);
        };
        if !stored.doc.is_live() {
            return Ok(None);
        }
        Ok(Some(stored.doc.to_ref(name)))
    }

    fn update_ref_cas(&self, update: &RefUpdate) -> HostResult<Ref> {
        self.cas_write(&update.name, &WriteTarget::Move(update.clone()))?;
        self.note_write();
        Ok(Ref {
            name: update.name.clone(),
            oid: update.new,
            updated_by: update.actor.clone().or_else(|| Some(Actor::from_env())),
            updated_at: Some(Timestamp::now()),
            schema: Some(crate::HOST_SCHEMA_VERSION),
        })
    }

    fn delete_ref_cas(&self, deletion: &RefDeletion) -> HostResult<()> {
        if deletion.expect != Expect::Any {
            self.require_cas(&deletion.name)?;
        }
        let current = self
            .read_ref(&deletion.name)?
            .filter(|stored| stored.doc.is_live());
        let stored = match (current, deletion.expect) {
            (None, Expect::Is(_)) => {
                return Err(HostError::NotFound(Box::new(NotFound {
                    what: "ref".into(),
                    key: deletion.name.to_string(),
                    hint: Some("it was already deleted; re-check the ref list".into()),
                })));
            }
            // Deleting what is not there is idempotent, exactly like the fs host.
            (None, Expect::Absent | Expect::Any) => return Ok(()),
            (Some(found), Expect::Absent) => {
                return Err(conflict(&deletion.name, None, found.advertised()));
            }
            (Some(found), Expect::Is(oid)) if found.advertised() != Some(oid) => {
                return Err(conflict(&deletion.name, Some(oid), found.advertised()));
            }
            (Some(found), _) => found,
        };
        // The tombstone replaces exactly the document we just read, so it carries
        // that etag: a concurrent move still loses the delete.
        let target = WriteTarget::Tombstone {
            oid: stored.doc.oid,
            actor: deletion.actor.clone(),
            if_match: Some(stored.etag.clone()),
        };
        self.cas_write(&deletion.name, &target)?;
        self.note_write();
        Ok(())
    }

    fn fetch_pack(&self, request: &PackRequest) -> HostResult<Pack> {
        if request.format != PackFormat::Raw {
            return Err(HostError::unsupported(
                format!("pack-format:{}", request.format.as_str()),
                "the S3 host stores gitiup raw packs; it has no git object database",
            )
            .with_hint("use the plain-git host (giti-xdw.3) to serve git packfiles"));
        }
        let haves: BTreeSet<String> = request.have.iter().map(Oid::hex).collect();
        let mut objects: Vec<(Namespace, Vec<u8>)> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut queue: Vec<Oid> = request.wants.clone();
        let mut wanted_bytes = 0usize;
        // A want may name a whole pack, which expands into its records, so the
        // walk is bounded rather than looping on a cyclic pile of packs.
        let mut budget = 100_000usize;
        while let Some(want) = queue.pop() {
            let hex = want.hex();
            if haves.contains(&hex) || !seen.insert(hex.clone()) {
                continue;
            }
            budget = budget.checked_sub(1).ok_or_else(|| {
                HostError::invalid(
                    "pack request",
                    "this fetch walks more than 100000 objects; ask for a narrower set of wants",
                )
            })?;
            // A want that names a stored pack contributes that pack's records,
            // not the pack body: a fetch answers wants, it does not hand back a
            // pack inside a pack.
            if let Some(object) = self.read(&self.pack_key(&want))? {
                let pack = Pack {
                    format: PackFormat::Raw,
                    bytes: object.bytes,
                };
                for (namespace, content) in pack.raw_objects()? {
                    let digest = Oid::hash_bytes(&content);
                    if haves.contains(&digest.hex()) || !seen.insert(digest.hex()) {
                        continue;
                    }
                    wanted_bytes += content.len();
                    objects.push((namespace, content));
                }
                continue;
            }
            let Some((namespace, key)) = self.find_kv(&want)? else {
                return Err(HostError::NotFound(Box::new(NotFound {
                    what: "blob".into(),
                    key: hex.clone(),
                    hint: Some(format!(
                        "'{}' is not in this store; push it first or check the digest",
                        &hex[..hex.len().min(12)]
                    )),
                })));
            };
            let Some(object) = self.read(&key)? else {
                return Err(HostError::NotFound(Box::new(NotFound {
                    what: "blob".into(),
                    key: key.clone(),
                    hint: Some("the listing went stale; try again".into()),
                })));
            };
            if Oid::hash_bytes(&object.bytes) != want {
                return Err(HostError::Storage(Box::new(crate::error::StorageError {
                    what: "verify blob".into(),
                    key,
                    message: "stored content does not match its content address".into(),
                    retryable: false,
                    source: None,
                })));
            }
            wanted_bytes += object.bytes.len();
            objects.push((namespace, object.bytes));
            if let Some(limit) = request.limit_bytes
                && wanted_bytes > limit
            {
                return Err(HostError::unsupported(
                    "pack-limit",
                    format!(
                        "the objects requested need more than the {limit} byte limit the request \
                         asked for",
                    ),
                )
                .with_hint("raise limit_bytes, or narrow the wants and haves"));
            }
        }
        Pack::from_raw_objects(objects)
    }

    fn put_pack(&self, pack: &Pack) -> HostResult<Oid> {
        pack.check_size()?;
        if pack.format != PackFormat::Raw {
            return Err(HostError::unsupported(
                format!("pack-format:{}", pack.format.as_str()),
                "the S3 host cannot ingest git packfiles; it has no git object database",
            )
            .with_hint(
                "use the plain-git host (giti-xdw.3), or convert the bundle to a raw pack",
            ));
        }
        let records = pack.raw_objects()?;
        let oid = pack.oid();
        let key = self.pack_key(&oid);
        // Packs are content addressed, so "already there" is a success rather than
        // a conflict — and noticing it saves the whole multipart upload.
        if self.head(&key)?.is_none() {
            let cond = if self.inner.capabilities.cas {
                PutCond::CreateOnly
            } else {
                PutCond::Unconditional
            };
            match self.write_raw(&key, &pack.bytes, cond) {
                Ok(_) => {}
                Err(err) if err.is_precondition_failed() => {}
                Err(err) => return Err(self.transport_error(&key, err)),
            }
        }
        for (namespace, content) in &records {
            self.put_cas(namespace, content)?;
        }
        self.note_write();
        Ok(oid)
    }
}

impl BlobStore for S3Host {
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> HostResult<Oid> {
        let oid = Oid::hash_bytes(content);
        let key = self.kv_key(namespace, &oid);
        if self.head(&key)?.is_some() {
            self.note_namespace(namespace);
            return Ok(oid);
        }
        let cond = if self.inner.capabilities.cas {
            // Create-only, so two writers of the same record cannot disagree
            // about what the digest stands for.
            PutCond::CreateOnly
        } else {
            PutCond::Unconditional
        };
        match self.write_raw(&key, content, cond) {
            Ok(_) => {}
            // Somebody else stored exactly these bytes: idempotent success.
            Err(err) if err.is_precondition_failed() => {}
            Err(err) => return Err(self.transport_error(&key, err)),
        }
        self.note_namespace(namespace);
        Ok(oid)
    }

    fn get(&self, oid: &Oid) -> HostResult<Option<Vec<u8>>> {
        let Some((_, key)) = self.find_kv(oid)? else {
            return Ok(None);
        };
        let Some(object) = self.read(&key)? else {
            return Ok(None);
        };
        if Oid::hash_bytes(&object.bytes) != *oid {
            return Err(HostError::Storage(Box::new(crate::error::StorageError {
                what: "verify blob".into(),
                key,
                message: "stored content does not match its content address".into(),
                retryable: false,
                source: None,
            })));
        }
        Ok(Some(object.bytes))
    }

    fn head(&self, oid: &Oid) -> HostResult<Option<BlobEntry>> {
        let Some((namespace, key)) = self.find_kv(oid)? else {
            return Ok(None);
        };
        Ok(self.head(&key)?.map(|meta| BlobEntry {
            namespace,
            oid: *oid,
            size: meta.size,
            created_at: meta.modified,
        }))
    }

    fn exists(&self, oid: &Oid) -> HostResult<bool> {
        Ok(self.find_kv(oid)?.is_some())
    }

    fn list_prefix(&self, pattern: &str) -> HostResult<Vec<BlobEntry>> {
        let prefix = Prefix::parse(pattern)?;
        let kv_root = self.inner.remote.kv_root();
        let listing_prefix = match &prefix.namespace {
            Some(namespace) => format!("{kv_root}/{namespace}"),
            None => kv_root,
        };
        let mut out: Vec<BlobEntry> = Vec::new();
        for meta in self.listing(&listing_prefix)? {
            let Some((namespace, digest)) = self.parse_kv_key(&meta.key) else {
                continue;
            };
            let Ok(oid) = Oid::from_hex(&digest) else {
                continue;
            };
            if !prefix.matches(&namespace, &oid) {
                continue;
            }
            out.push(BlobEntry {
                namespace,
                oid,
                size: meta.size,
                created_at: meta.modified,
            });
        }
        out.sort_by_key(BlobEntry::key);
        Ok(out)
    }
}

impl Host for S3Host {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities
    }

    fn describe(&self) -> HostInfo {
        HostInfo {
            name: self.inner.remote.name.clone(),
            kind: HostKind::S3,
            url: Some(self.inner.remote.redacted_url()),
            store_prefix: self.inner.remote.store_prefix.clone(),
            capabilities: self.inner.capabilities,
            implemented_by: implemented_by("s3"),
            schema_version: crate::HOST_SCHEMA_VERSION,
        }
    }
}

impl fmt::Display for S3Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {}/",
            self.describe().name,
            self.inner.remote.redacted_url()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote_with(options: &[(&str, &str)]) -> RemoteConfig {
        let mut remote = RemoteConfig::new("origin", "s3://gitiup-forge/my-repo").expect("url");
        for (key, value) in options {
            remote = remote.with_option(*key, *value);
        }
        remote
    }

    #[test]
    fn every_documented_option_is_read() {
        let remote = remote_with(&[
            ("region", "eu-central-1"),
            ("endpoint", "http://127.0.0.1:9000"),
            ("profile", "ci-writer"),
            ("force-path-style", "true"),
            ("require-versioning", "false"),
            ("conditional-writes", "off"),
            ("multipart-threshold-mib", "32"),
            ("part-size-mib", "16"),
            ("ref-cache-ttl", "90s"),
            ("cas-attempts", "9"),
            ("cas-backoff", "5ms"),
            ("cas-backoff-cap", "1s"),
        ]);
        let (options, advice) = S3Options::from_remote(&remote).expect("every key is known");
        assert!(advice.is_empty(), "unexpected advice: {advice:?}");
        assert_eq!(options.region.as_deref(), Some("eu-central-1"));
        assert_eq!(options.endpoint.as_deref(), Some("http://127.0.0.1:9000"));
        assert_eq!(options.profile.as_deref(), Some("ci-writer"));
        assert!(options.force_path_style);
        assert!(!options.require_versioning);
        assert_eq!(options.conditional_writes, ConditionalWrites::Off);
        assert_eq!(options.threshold_bytes(), 32 * MIB);
        assert_eq!(options.ref_cache_ttl, Duration::from_secs(90));
        assert_eq!(options.cas_attempts, 9);
        assert_eq!(options.cas_backoff, Duration::from_millis(5));
        assert_eq!(options.cas_backoff_cap, Duration::from_secs(1));
    }

    #[test]
    fn defaults_are_the_safe_shape() {
        let (options, advice) = S3Options::from_remote(&remote_with(&[])).expect("nothing to read");
        assert!(advice.is_empty());
        assert!(
            options.require_versioning,
            "versioning is required until the operator says otherwise"
        );
        assert_eq!(options.conditional_writes, ConditionalWrites::Auto);
        assert_eq!(options.ref_cache_ttl, DEFAULT_REF_CACHE_TTL);
        assert!(options.cas_attempts > 0, "a 412 gets a retry budget");
        assert!(options.cas_backoff < options.cas_backoff_cap);
        assert!(options.part_size >= 5 * MIB, "S3's minimum part size");
    }

    #[test]
    fn an_option_this_host_does_not_read_becomes_advice() {
        // Not an error: another host reads the same table. Silent is the failure
        // mode we are avoiding.
        let (options, advice) =
            S3Options::from_remote(&remote_with(&[("timeout", "30s")])).expect("not fatal");
        assert_eq!(options.ref_cache_ttl, DEFAULT_REF_CACHE_TTL);
        assert_eq!(advice.len(), 1, "{advice:?}");
        assert!(advice[0].contains("timeout"), "{advice:?}");
        assert!(advice[0].contains("does not read"), "{advice:?}");
    }

    #[test]
    fn the_ref_cache_can_be_turned_off_but_not_misread() {
        for off in ["0s", "0", "off", "none", "never", "no"] {
            let (options, _) =
                S3Options::from_remote(&remote_with(&[("ref-cache-ttl", off)])).expect(off);
            assert_eq!(options.ref_cache_ttl, Duration::ZERO, "{off} must disable");
        }
        let (options, _) =
            S3Options::from_remote(&remote_with(&[("ref-cache-ttl", "250ms")])).expect("ms");
        assert_eq!(options.ref_cache_ttl, Duration::from_millis(250));
        for junk in ["soon", "ten seconds", ""] {
            let err =
                S3Options::from_remote(&remote_with(&[("ref-cache-ttl", junk)])).expect_err(junk);
            assert!(err.to_string().contains("timeout"), "{err}");
            assert!(err.hint().unwrap().contains("250ms"), "{err}");
        }
    }

    #[test]
    fn bad_values_are_refused_with_the_shape_that_would_work() {
        let err = S3Options::from_remote(&remote_with(&[("conditional-writes", "maybe")]))
            .expect_err("not a value");
        assert!(err.to_string().contains("conditional-writes"), "{err}");
        assert!(err.hint().is_some(), "{err}");

        let err = S3Options::from_remote(&remote_with(&[("cas-attempts", "lots")]))
            .expect_err("not a count");
        assert!(err.hint().unwrap().contains("4"), "{err}");

        // S3 refuses parts below 5 MiB; saying so now beats a failed upload later.
        let err =
            S3Options::from_remote(&remote_with(&[("part-size-mib", "1")])).expect_err("too small");
        assert!(err.to_string().contains("5"), "{err}");
    }

    #[test]
    fn cas_retry_sleeps_are_bounded_and_grow() {
        // The backoff is what keeps a 412 flinch from becoming a stampede, so it
        // must grow and it must stop.
        let fast = S3Options {
            cas_backoff: Duration::from_millis(1),
            cas_backoff_cap: Duration::from_millis(4),
            ..S3Options::default()
        };
        assert_eq!(fast.cas_backoff, Duration::from_millis(1));
        assert!(fast.cas_backoff_cap >= fast.cas_backoff);
        assert!(
            DEFAULT_CAS_BACKOFF < Duration::from_millis(100),
            "stays quick"
        );
    }
}

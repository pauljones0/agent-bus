//! Durable content-addressed artifact bytes + per-agent quota accounting.
//!
//! Source-backed port of the transitional `broker.py` artifact surface
//! (text-only contract, current-tree line numbers): `ART_DIR` 39,
//! `ART_MAX`/`CHUNK_MAX` 52-53, `uploads` 56, `art_usage` 78,
//! `art_put` 1086-1116, `art_get` 1118-1128, `art_init` 1130-1155,
//! `art_chunk` 1157-1185, `art_commit` 1187-1229, `art_abort`
//! 1231-1245, `art_range` 1247-1269, `art_stat` 1271-1279, `limits`
//! 1495-1501, `stats` 1517-1527, `token_issue` quota grant 1301-1303,
//! WAL `art_own` replay 651-653 + compaction 698-702, startup
//! staging cleanup 1552-1556, disconnect `my_uploads` cleanup
//! 1533-1539, client streaming (`busclient.py` 1077-1179, `bus`
//! `art-put`/`art-get` 338-343/752-770). Wire auth/visibility rule:
//! any authenticated agent reads any committed sha (no per-artifact
//! ACL); chunk/commit/abort need owner-or-admin (`info.agent == "*"`,
//! never open-mode); every authed op refreshes presence (wire
//! `handle`, never `ping`).
//!
//! Native layout: `ArtifactStore` owns `dir` (`<wal-parent>/artifacts`,
//! matching legacy `DATA/artifacts` for `DATA/wal.log`), committed
//! objects `dir/<sha64>`, private staging `dir/.up-<hex16>` (chunked
//! uploads) and `dir/.put-<hex16>` (single puts). Usage is
//! `agent -> u64` bytes, seeded at boot from WAL `art_own`
//! (`crate::wal::replay_art_usage`) and charged only after bytes +
//! WAL are both durable (commit-before-success); `quota_denied` is a
//! live memory counter (reset on restart, matching legacy `stats`).
//! Dedup still charges (legacy); there is no uncharge/delete op.
//!
//! Pending chunked uploads are admission-bounded ([`StagingLimits`]:
//! finite global/per-owner count and declared-byte caps, covering
//! both `Active` and retained `CommittedCleanupPending` uploads).
//! `init_upload` reserves atomically under the uploads lock BEFORE
//! creating staging, rolls the reservation back when staging creation
//! fails, and holds it until physical cleanup is confirmed (pop on
//! unlink success or already-gone); retained cleanup failures keep
//! holding it, so aggregate retained state is bounded, not just one
//! retry. Durable committed usage stays separate: releasing a staging
//! reservation never uncharges, and WAL success never recomputes or
//! double-charges. Single-put `.put-*` staging is transient within one
//! RPC (never retained in the map) and is outside these bounds; each
//! such file is at most `ART_MAX` (see `docs/NATIVE_ARTIFACTS.md`).
//!
//! Correctness improvements over legacy (see `docs/NATIVE_ARTIFACTS.md`):
//! single puts stage privately then atomic-rename (legacy wrote final
//! directly, leaving torn bytes on crash); `art_own` WAL append+fsync
//! runs before ack (legacy group-commit only, no `durable` support);
//! sha ids must be 64 lowercase hex (legacy accepted any slash-free
//! name, so staging `.up-*` was readable via `art_get`); base64 and
//! quota parsing fail closed with explicit errors (legacy stripped
//! non-alphabet and crashed the connection on malformed quota);
//! reservation charging with rollback (concurrent puts serialize on
//! quota, failures never charge). Compatibility: legitimate hex-sha
//! single-line-base64 integer-quota traffic is unaffected; exotic
//! shas/whitespace/non-numeric quotas that legacy tolerated now fail
//! explicitly instead of leaking or crashing.
//!
//! Lock discipline (no global lock across slow IO): the global
//! usage/uploads maps are held only for fast lookup/insert/pop and
//! check+charge/uncharge; artifact file IO (hash, read, write,
//! rename, fsync) and WAL appends run outside those locks. Each
//! pending upload has its own mutex, held across its own file IO so
//! concurrent chunks/commits/aborts/disconnects for one upload
//! serialize without blocking other uploads. Reservation order is
//! per-upload then usage then (briefly, for the small `art_own`
//! record) the WAL; no path takes them in reverse. Staging limits are
//! copied out of their own mutex before the uploads lock (never
//! nested); the admission check, count/byte reservation, and map
//! insert are one atomic critical section. Initialization acquires its
//! new per-upload mutex before publishing the handle and keeps it through
//! file creation; cancellation can only observe the completed creation or
//! a terminal creation failure. No code waits for a per-upload mutex while
//! holding the uploads map mutex.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

/// Maximum artifact bytes per object (legacy `ART_MAX`, `broker.py:52`).
pub const ART_MAX: u64 = 32 * 1024 * 1024;
/// Maximum raw bytes per chunk/range reply (legacy `CHUNK_MAX`, `broker.py:53`).
pub const CHUNK_MAX: u64 = 4 * 1024 * 1024;
/// Committed object id length: 64 lowercase hex (sha256).
pub const SHA_HEX_LEN: usize = 64;
/// Staging upload id length: 16 lowercase hex (64-bit random, legacy `uuid.hex[:16]`).
pub const UPLOAD_ID_LEN: usize = 16;
/// Chunked-upload staging prefix (legacy `.up-`, `broker.py:1144`).
pub const STAGING_UP_PREFIX: &str = ".up-";
/// Single-put staging prefix (native; legacy wrote final directly).
pub const STAGING_PUT_PREFIX: &str = ".put-";
/// Client streaming threshold: files/stdin larger than 1 MiB use
/// init/chunk/commit (legacy `bus` 755 + `busclient` 1082/1174).
pub const CLIENT_STREAM_THRESHOLD: u64 = 1024 * 1024;
/// Client put chunk size (legacy `busclient` 256 KiB, 1114/1129).
pub const PUT_STREAM_CHUNK: usize = 256 * 1024;
/// Client get chunk size (legacy `busclient` 1 MiB, 1153).
pub const GET_STREAM_CHUNK: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------
// SHA-256 via maintained `sha2` crate (thin adapter, same public API)
// ---------------------------------------------------------------------------

/// Lowercase hex of a 32-byte digest (trivial formatting, not crypto).
fn hex32(sum: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in sum {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

/// Streaming SHA-256 hasher (thin adapter over maintained `sha2::Sha256`;
/// matches `hashlib.sha256`). Public API preserved for existing callers.
#[derive(Clone)]
pub struct Sha256 {
    inner: sha2::Sha256,
}

impl Sha256 {
    pub fn new() -> Self {
        use sha2::Digest as _;
        Sha256 { inner: sha2::Sha256::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        use sha2::Digest as _;
        let out = self.inner.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-256 hex digest (lowercase, 64 chars; matches `hashlib.sha256().hexdigest()`).
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    let sum = sha2::Sha256::digest(data);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&sum);
    hex32(arr)
}

// ---------------------------------------------------------------------------
// Base64 via maintained `base64` crate (thin adapter, same public API)
// ---------------------------------------------------------------------------

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::Engine as _;

/// Standard base64 engine: canonical padding required (len % 4 == 0,
/// padding only at end, whitespace/alphabet rejected), trailing-bit
/// leniency preserved (legacy never enforced trailing bits; only shape
/// strict). All decode failures map to `"bad base64"` (no leak).
const B64_ENGINE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

/// Standard base64 encode (matches `base64.b64encode().decode()`).
pub fn base64_encode(data: &[u8]) -> String {
    B64_ENGINE.encode(data)
}

/// Strict standard base64 decode. Empty decodes to empty (legacy).
/// Fails closed as `"bad base64"` on wrong length, bad alphabet
/// (including whitespace, which legacy `validate=False` stripped),
/// or misplaced padding. Trailing-bit checks are lenient (legacy
/// never enforced them); only shape is strict. Backed by maintained
/// `base64` crate (STANDARD, canonical padding, trailing bits allowed).
pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    B64_ENGINE.decode(s.as_bytes()).map_err(|_| "bad base64".to_string())
}

/// Maximum base64 chars that can decode within `max_raw` bytes.
/// Callers check encoded length first so a hostile 256 MiB frame is
/// rejected without a 192 MiB allocation.
pub fn max_b64_len(max_raw: u64) -> u64 {
    max_raw.div_ceil(3).saturating_mul(4)
}

// ---------------------------------------------------------------------------
// Opaque ids + quota parsing (checked arithmetic, fail closed)
// ---------------------------------------------------------------------------

/// True for committed object ids: exactly 64 lowercase hex.
/// Native tightens legacy (any slash-free name) so staging `.up-*`
/// is never readable via `art_get`/`art_range`/`art_stat`; see docs.
pub fn is_valid_sha(s: &str) -> bool {
    s.len() == SHA_HEX_LEN
        && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// True for server-generated staging ids: exactly 16 lowercase hex.
/// Client-supplied upload ids are map keys only (never path-built),
/// so lookups accept any string and miss as `unknown upload`; this
/// validates generated ids before path construction.
pub fn is_valid_upload_id(s: &str) -> bool {
    s.len() == UPLOAD_ID_LEN
        && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parsed `art_quota_bytes` policy: unlimited (missing/null), a finite
/// byte limit, or malformed (fail-closed deny, never crash like legacy
/// `int(q)` on bad types).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quota {
    Unlimited,
    Limited(u64),
    Malformed,
}

/// Parse the preserved `Policy::extra["art_quota_bytes"]` value.
/// Integers `>= 0` limit; missing/null mean unlimited; negative
/// integers deny all (limit 0, matching legacy `usage+size > negative`
/// for every non-empty write); finite integral floats truncate toward
/// zero like Python `int()`; huge floats beyond `u64` mean unlimited
/// (larger than any reachable usage); anything else is malformed.
pub fn parse_quota(v: Option<&serde_json::Value>) -> Quota {
    use serde_json::Value;
    let Some(v) = v else {
        return Quota::Unlimited;
    };
    match v {
        Value::Null => Quota::Unlimited,
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                return Quota::Limited(u);
            }
            if let Some(i) = n.as_i64() {
                if i < 0 {
                    return Quota::Limited(0);
                }
                return Quota::Limited(i as u64);
            }
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Quota::Malformed;
                }
                if f < 0.0 {
                    return Quota::Limited(0);
                }
                if f > u64::MAX as f64 {
                    return Quota::Unlimited;
                }
                return Quota::Limited(f.trunc() as u64);
            }
            Quota::Malformed
        }
        _ => Quota::Malformed,
    }
}

/// Quota gate with checked arithmetic in EVERY mode: `usage + size`
/// overflow denies (never wraps to allow, never panics); unlimited
/// allows only when the addition succeeds (overflow denies
/// conservatively, consistent with [`ArtifactStore::restore_usage`]
/// saturation which caps at `u64::MAX` to keep the gate denying);
/// malformed denies. Empty (`size == 0`) allows whenever the addition
/// succeeds (even at saturated `MAX`, `MAX + 0 == MAX`). Returns `Ok`
/// on allow, `Err("artifact quota exceeded")` on deny (same string
/// for over-quota, overflow, and malformed so config shape never leaks).
pub fn check_quota(usage: u64, size: u64, quota: Quota) -> Result<(), String> {
    match quota {
        Quota::Unlimited => match usage.checked_add(size) {
            Some(_) => Ok(()),
            None => Err("artifact quota exceeded".to_string()),
        },
        Quota::Malformed => Err("artifact quota exceeded".to_string()),
        Quota::Limited(limit) => match usage.checked_add(size) {
            Some(total) if total <= limit => Ok(()),
            _ => Err("artifact quota exceeded".to_string()),
        },
    }
}

// ---------------------------------------------------------------------------
// Staging admission bounds (pending chunked uploads, Active + retained)
// ---------------------------------------------------------------------------

/// Default global cap: at most 1024 pending chunked uploads broker-wide
/// (active plus retained cleanup-pending). Finite and generous: ordinary
/// coordination holds a handful; the bound only bites runaway clients.
pub const DEFAULT_MAX_UPLOADS_GLOBAL: u64 = 1024;
/// Default per-owner cap: at most 128 pending chunked uploads per
/// authenticated agent name (active plus retained cleanup-pending).
pub const DEFAULT_MAX_UPLOADS_PER_OWNER: u64 = 128;
/// Default global cap: at most 4 GiB of declared pending-upload bytes
/// broker-wide (sum of `size` over active plus retained uploads).
/// Declared bytes upper-bound actual staging disk use (chunks enforce
/// `received + len <= size`), so this caps aggregate staging at 4 GiB
/// even if every upload declares `ART_MAX`.
pub const DEFAULT_MAX_STAGING_BYTES_GLOBAL: u64 = 4 * 1024 * 1024 * 1024;
/// Default per-owner cap: at most 512 MiB of declared pending-upload
/// bytes per authenticated agent name.
pub const DEFAULT_MAX_STAGING_BYTES_PER_OWNER: u64 = 512 * 1024 * 1024;

/// `art_init` denial when a staging count bound is hit (global or
/// per-owner; the two are deliberately one string so the response does
/// not reveal which bound or its value, mirroring the quota error).
pub const STAGING_COUNT_ERROR: &str = "too many pending uploads";
/// `art_init` denial when a staging declared-byte bound is hit (global
/// or per-owner; likewise one string for both scopes).
pub const STAGING_BYTES_ERROR: &str = "pending upload bytes exceeded";

/// Finite admission bounds for pending chunked uploads, covering both
/// `Active` uploads and retained `CommittedCleanupPending` orphans
/// (cleanup failures keep holding their reservation until physical
/// cleanup is confirmed, so bounded retries cannot accumulate unbounded
/// retained state). Counts and declared bytes use `u64` with checked
/// admission (`>=` on counts, `checked_add` then `>` on bytes); a zero
/// bound denies everything in that dimension. Committed-usage quota
/// ([`Quota`]) is orthogonal: staging admission never charges usage,
/// and releasing a reservation never uncharges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagingLimits {
    pub max_uploads_global: u64,
    pub max_uploads_per_owner: u64,
    pub max_declared_bytes_global: u64,
    pub max_declared_bytes_per_owner: u64,
}

impl Default for StagingLimits {
    fn default() -> Self {
        StagingLimits {
            max_uploads_global: DEFAULT_MAX_UPLOADS_GLOBAL,
            max_uploads_per_owner: DEFAULT_MAX_UPLOADS_PER_OWNER,
            max_declared_bytes_global: DEFAULT_MAX_STAGING_BYTES_GLOBAL,
            max_declared_bytes_per_owner: DEFAULT_MAX_STAGING_BYTES_PER_OWNER,
        }
    }
}

impl StagingLimits {
    /// Tiny deterministic bounds for tests (exact values asserted by
    /// callers; production always uses [`StagingLimits::default`]).
    pub fn for_test(
        max_uploads_global: u64,
        max_uploads_per_owner: u64,
        max_declared_bytes_global: u64,
        max_declared_bytes_per_owner: u64,
    ) -> Self {
        StagingLimits {
            max_uploads_global,
            max_uploads_per_owner,
            max_declared_bytes_global,
            max_declared_bytes_per_owner,
        }
    }
}

// ---------------------------------------------------------------------------
// Durable store: committed objects, private staging, quota + uploads
// ---------------------------------------------------------------------------

/// Pending-upload lifecycle: `Active` accepts chunks/commit/abort;
/// `Committed`/`Aborted` are terminal with staging already unlinked
/// (the map pop already happened or is imminent; late ops miss as
/// `unknown upload`). `CommittedCleanupPending` is committed
/// (WAL `art_own` durable, charge kept, receipt valid) but the owned
/// staging unlink failed; it is retained for explicit `art_abort`
/// retry (no recommit/double-charge, no uncharge), counted in
/// `staging_cleanup_failed`, and never presented as `unknown upload`
/// to owners (owners get `already committed (staging cleanup
/// pending...)`, non-owners still miss as `unknown` to hide existence).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadState {
    Active,
    Committed,
    Aborted,
    CommittedCleanupPending,
}

/// One pending chunked upload (legacy `uploads[uid]`, `broker.py:56`).
/// All fields sit behind the per-upload mutex; the global map holds
/// `Arc<Mutex<..>>` so disconnect/abort waits for an in-progress
/// commit instead of unlinking under it.
#[derive(Clone, Debug)]
pub struct PendingUpload {
    pub agent: String,
    pub size: u64,
    pub sha: Option<String>,
    pub path: PathBuf,
    pub received: u64,
    pub state: UploadState,
}

/// Durability failpoints for tests (production always `ART_FAIL_NONE`,
/// mirroring `crate::tokens` persist failpoints). Pre-commit failures
/// leave `final` untouched (safe retry); post-rename/post-link
/// dir-fsync failures leave bytes visible but the directory entry
/// possibly non-durable (caller rolls back the charge, retry dedups
/// after establishing durability). No failpoint deletes a valid object.
pub const ART_FAIL_NONE: u8 = 0;
/// Fail dedup file fsync (existing valid object data barrier).
pub const ART_FAIL_DEDUP_FILE_FSYNC: u8 = 1;
/// Fail dedup dir fsync (existing valid object entry barrier).
pub const ART_FAIL_DEDUP_DIR_FSYNC: u8 = 2;
/// Fail new-put dir fsync (after rename, before ack).
pub const ART_FAIL_PUT_DIR_FSYNC: u8 = 3;
/// Fail new-publish dir fsync (after hardlink, before ack).
pub const ART_FAIL_PUBLISH_DIR_FSYNC: u8 = 4;
/// Fail artifact-dir parent fsync (immediate-parent entry barrier,
/// last in the ancestor chain; earlier ancestors are synced first so
/// ordering tests observe top-down establishment before the failure).
pub const ART_FAIL_PARENT_FSYNC: u8 = 5;
/// Fail artifact-dir ancestor fsync (topmost ancestor entry barrier,
/// first in the chain; no barrier is established before the failure).
/// Together with [`ART_FAIL_PARENT_FSYNC`] proves every supported
/// nested `create_dir_all` level is attempted, including on retry
/// after a failed first sync and when the dir is already visible
/// (`AlreadyExists`, no existence skip).
pub const ART_FAIL_ANCESTOR_FSYNC: u8 = 6;

/// Existing-object validation outcome (single-handle, no blind
/// metadata existence). `Valid` carries the opened, validated handle
/// so the dedup durability barrier fsyncs the same inode without a
/// reopen TOCTOU.
enum Validated {
    Missing,
    Valid(std::fs::File),
    Invalid,
}

/// Pending-upload map plus live staging admission accounting, under
/// one mutex so the admission check, count/byte reservation, and map
/// insert/pop are atomic. Every map entry holds exactly one
/// reservation (its `agent` + declared `size`); `pop_upload` releases
/// exactly one, and a double pop releases nothing. Per-owner entries
/// are removed when their count reaches zero, so the accounting itself
/// cannot grow without bound over distinct past owners. Terminal
/// `Committed`/`Aborted` entries exist only in the micro-window between
/// the state set (under the per-upload lock) and the pop; retained
/// `CommittedCleanupPending` and failed-abort `Active` entries keep
/// holding their reservation until physical cleanup is confirmed.
struct UploadsState {
    map: HashMap<String, Arc<Mutex<PendingUpload>>>,
    global_count: u64,
    global_bytes: u64,
    per_owner: HashMap<String, (u64, u64)>,
}

/// Observation points in the actual initialization path. Production uses
/// a no-op observer; unit tests inspect lock/reservation invariants and
/// exercise ordinary local creation failures without timing assumptions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UploadInitPhase {
    BeforeCreate,
    AfterCreate,
}

impl UploadsState {
    fn new() -> Self {
        UploadsState {
            map: HashMap::new(),
            global_count: 0,
            global_bytes: 0,
            per_owner: HashMap::new(),
        }
    }
}

/// Durable artifact store: `dir` holds committed `<sha64>` objects
/// plus private `.up-*`/`.put-*` staging. Usage/uploads are
/// mutex-guarded; every method documents its lock scope (global
/// locks never cross file IO; per-upload locks do). `quota_denied`
/// and `staging_cleanup_failed` are live memory counters (reset on
/// restart, like legacy `stats`); `unlink_fail_remaining` is a
/// test-only owned-staging unlink failpoint (production always 0,
/// no unbounded retry workers, retries are explicit client `art_abort`).
/// `staging_limits` holds the finite admission bounds (production:
/// [`StagingLimits::default`], never mutated; tests shrink via
/// [`ArtifactStore::set_staging_limits_for_test`]).
pub struct ArtifactStore {
    dir: PathBuf,
    usage: Mutex<HashMap<String, u64>>,
    uploads: Mutex<UploadsState>,
    staging_limits: Mutex<StagingLimits>,
    quota_denied: AtomicU64,
    staging_cleanup_failed: AtomicU64,
    unlink_fail_remaining: AtomicU64,
}

impl ArtifactStore {
    /// Create `dir` (fail closed) and delete stale staging
    /// (`.up-*`/`.put-*`, crash leftovers; legacy deleted `.up-*`
    /// only, `broker.py:1552-1556`). Unconditionally fsyncs every
    /// ancestor directory entry for the supported arbitrary nested
    /// `create_dir_all` path, top-down from the topmost parent to the
    /// immediate parent, before any publication ack (every successful
    /// init, including retries after a failed first sync and restarts
    /// where the dir is already visible; no exemption based on prior
    /// metadata existence or `AlreadyExists` visibility). If any
    /// ancestor cannot be synced, startup fails closed rather than
    /// publishing into a possibly non-durable namespace. Bare
    /// relative dirs (empty parent) sync `"."` (CWD holds the entry,
    /// mirroring `crate::migration` parent handling); filesystem root
    /// (`/`, no parent) needs no barrier; `"."` as `dir` self-syncs
    /// `"."` (best-effort self barrier, preserving prior behavior;
    /// the CWD parent entry is outside the syntactic path and is not
    /// claimed durable). This barrier orders entry-before-ack; it does
    /// not by itself prove power-loss-safe namespaces (no visibility
    /// claim, no child-only claim; deterministic failpoint/order tests
    /// prove attempt ordering and retry, not power loss). Usage starts
    /// empty; the wire seeds it from WAL `art_own` before serving.
    pub fn new(dir: PathBuf) -> Result<Self, String> {
        Self::new_with_failpoint(dir, ART_FAIL_NONE)
    }

    /// Test hook: `new` with durability failpoint. Production always
    /// passes [`ART_FAIL_NONE`]; tests pass
    /// [`ART_FAIL_PARENT_FSYNC`] (fail the immediate parent, last in
    /// the chain, after syncing earlier ancestors) or
    /// [`ART_FAIL_ANCESTOR_FSYNC`] (fail the topmost ancestor, first
    /// in the chain, before any barrier) to prove ancestor-entry
    /// error propagation, including on retry after a failed first
    /// sync and when the dir is already visible (no existence skip,
    /// no `AlreadyExists` exemption). Limits are production
    /// defaults; combine with
    /// [`ArtifactStore::set_staging_limits_for_test`] for tiny bounds.
    pub fn new_with_failpoint(dir: PathBuf, failpoint: u8) -> Result<Self, String> {
        Self::new_inner(dir, failpoint, StagingLimits::default())
    }

    /// Test hook: `new` with explicit staging admission bounds
    /// (deterministic tiny-limit tests). Durability failpoint is
    /// [`ART_FAIL_NONE`]; combine with
    /// [`ArtifactStore::set_unlink_failpoint_for_test`] for cleanup
    /// fault tests. Production always uses [`StagingLimits::default`].
    pub fn new_with_limits(dir: PathBuf, limits: StagingLimits) -> Result<Self, String> {
        Self::new_inner(dir, ART_FAIL_NONE, limits)
    }

    fn new_inner(dir: PathBuf, failpoint: u8, limits: StagingLimits) -> Result<Self, String> {
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("artifact dir unavailable: {e}"))?;
        Self::fsync_ancestors_with_failpoint(&dir, failpoint)?;
        Self::clean_staging(&dir);
        Ok(ArtifactStore {
            dir,
            usage: Mutex::new(HashMap::new()),
            uploads: Mutex::new(UploadsState::new()),
            staging_limits: Mutex::new(limits),
            quota_denied: AtomicU64::new(0),
            staging_cleanup_failed: AtomicU64::new(0),
            unlink_fail_remaining: AtomicU64::new(0),
        })
    }

    /// Ordered ancestor directories to fsync after `create_dir_all`,
    /// top-down from the topmost parent to the immediate parent.
    /// `"/"` yields `[]` (parentless root, no entry to establish);
    /// `"artifacts"` yields `["."]` (CWD holds the entry);
    /// `"sub/artifacts"` yields `[".", "sub"]` (CWD holds `sub`,
    /// `sub` holds `artifacts`); `"/tmp/x/artifacts"` yields
    /// `["/", "/tmp", "/tmp/x"]`; `"."` as `dir` yields `["."]`
    /// (self-sync, best-effort, preserving prior empty-parent
    /// behavior; the CWD parent is outside the path). Syntactic only
    /// (no canonicalization, no existence probe): over-syncing an
    /// already-durable ancestor is safe, under-syncing a newly
    /// created one is not. Every init syncs the full chain
    /// unconditionally, so retries after a failed barrier and
    /// restarts where the dir is already visible (`AlreadyExists`)
    /// still establish all entries.
    fn ancestor_fsync_chain(dir: &Path) -> Vec<PathBuf> {
        let mut rev: Vec<PathBuf> = Vec::new();
        let mut current = dir;
        loop {
            match current.parent() {
                None => break,
                Some(p) if p.as_os_str().is_empty() => {
                    rev.push(PathBuf::from("."));
                    break;
                }
                Some(p) => {
                    rev.push(p.to_path_buf());
                    if p == Path::new(".") {
                        break;
                    }
                    // `p` is strictly shorter than `current` (parent
                    // strips one component), so this terminates; the
                    // chain length is bounded by the path depth.
                    current = p;
                }
            }
        }
        rev.reverse();
        rev
    }

    /// Fsync one directory, mapping errors to the init failure string.
    /// `is_immediate` selects the legacy immediate-parent message
    /// (`"artifact dir unavailable: parent fsync..."`, preserved for
    /// compatibility) versus the ancestor message for newly covered
    /// levels (`"artifact dir unavailable: ancestor fsync..."`).
    fn fsync_one_dir(dir: &Path, is_immediate: bool) -> Result<(), String> {
        let label = if is_immediate { "parent" } else { "ancestor" };
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("artifact dir unavailable: {label} fsync: {e}"))?;
        Ok(())
    }

    /// The single ancestor-sync loop, shared by production init and
    /// the order-proving recorder (there is no copied loop): iterate
    /// `chain` top-down, record each attempt into `record` when `Some`
    /// (including the failed one), sync all earlier entries for real,
    /// then fail positionally at `fail_at` without that entry's real
    /// fsync (immediate-parent vs ancestor labels preserved).
    /// `fail_at: None` syncs the full chain for real. Empty chains
    /// succeed on `None` and fail closed on any positional failpoint.
    /// Otherwise fails closed on the first real IO error.
    fn run_ancestor_chain(
        chain: &[PathBuf],
        fail_at: Option<usize>,
        mut record: Option<&mut Vec<PathBuf>>,
    ) -> Result<(), String> {
        if chain.is_empty() {
            if fail_at.is_some() {
                return Err("artifact dir unavailable: parent fsync".to_string());
            }
            return Ok(());
        }
        let last = chain.len() - 1;
        for (i, ancestor) in chain.iter().enumerate() {
            if let Some(r) = record.as_mut() {
                r.push(ancestor.clone());
            }
            if Some(i) == fail_at {
                let label = if i == last { "parent" } else { "ancestor" };
                return Err(format!("artifact dir unavailable: {label} fsync"));
            }
            let is_immediate = i == last;
            Self::fsync_one_dir(ancestor, is_immediate)?;
        }
        Ok(())
    }

    /// Fsync the full ancestor chain with failpoint injection.
    /// Unconditional: every init calls this, so retries after a failed
    /// first sync still establish all barriers (no `existed` skip, no
    /// `AlreadyExists` visibility exemption). Top-down order (topmost
    /// first, immediate parent last). [`ART_FAIL_ANCESTOR_FSYNC`]
    /// fails before any barrier (first); [`ART_FAIL_PARENT_FSYNC`]
    /// syncs all earlier ancestors successfully, then fails on the
    /// immediate parent (last) without attempting its real fsync, so
    /// ordering tests observe file-before-dir-style prefix success.
    /// Empty chains (parentless root) succeed on [`ART_FAIL_NONE`]
    /// and fail closed on either barrier failpoint (proving the
    /// failpoint path is honored even when no real fsync is needed).
    /// Otherwise fails closed on the first real IO error so
    /// publication never acks into a non-durable namespace. The loop
    /// itself is [`ArtifactStore::run_ancestor_chain`], shared with
    /// the recorder (semantic failpoints map to positional ones here).
    fn fsync_ancestors_with_failpoint(dir: &Path, failpoint: u8) -> Result<(), String> {
        let chain = Self::ancestor_fsync_chain(dir);
        if chain.is_empty() {
            if failpoint == ART_FAIL_PARENT_FSYNC {
                return Err("artifact dir unavailable: parent fsync".to_string());
            }
            if failpoint == ART_FAIL_ANCESTOR_FSYNC {
                return Err("artifact dir unavailable: ancestor fsync".to_string());
            }
            return Ok(());
        }
        if failpoint == ART_FAIL_ANCESTOR_FSYNC {
            return Err("artifact dir unavailable: ancestor fsync".to_string());
        }
        let fail_at = if failpoint == ART_FAIL_PARENT_FSYNC {
            Some(chain.len() - 1)
        } else {
            None
        };
        Self::run_ancestor_chain(&chain, fail_at, None)
    }

    /// Test-only chain runner: attempt recording plus positional
    /// failure injection, running the actual production loop
    /// ([`ArtifactStore::run_ancestor_chain`], not a copy). Records
    /// every attempted ancestor in order (including the failed one),
    /// syncs all earlier entries for real, then fails at `fail_at`
    /// without its real fsync. `fail_at: None` syncs the full chain
    /// for real. Returns the same init failure strings as production
    /// (immediate vs ancestor labels preserved). Unit tests use this
    /// to prove top-down ordering, retry re-establishment, and
    /// `AlreadyExists` no-skip without claiming power-loss proof.
    #[allow(dead_code)]
    fn fsync_chain_with_recorder(
        chain: &[PathBuf],
        fail_at: Option<usize>,
        record: &mut Vec<PathBuf>,
    ) -> Result<(), String> {
        Self::run_ancestor_chain(chain, fail_at, Some(record))
    }

    /// Best-effort staging sweep (per-file ignore, like legacy).
    fn clean_staging(dir: &Path) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(STAGING_UP_PREFIX) || name.starts_with(STAGING_PUT_PREFIX) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Live charged bytes for `agent` (fast map read, no IO).
    pub fn usage_of(&self, agent: &str) -> u64 {
        *self.usage.lock().unwrap().get(agent).unwrap_or(&0)
    }

    /// Live quota-denial counter (memory-only, reset on restart).
    pub fn quota_denied(&self) -> u64 {
        self.quota_denied.load(Ordering::SeqCst)
    }

    fn inc_quota_denied(&self) {
        self.quota_denied.fetch_add(1, Ordering::SeqCst);
    }

    /// Live owned-staging cleanup-failure counter (memory-only, reset
    /// on restart, like `quota_denied`). Incremented once per failed
    /// `disconnect`/`commit`/`abort` staging unlink (excluding
    /// `NotFound` already-gone, which counts as success). Exposed via
    /// wire `stats.staging_cleanup_failed` so disconnect failures
    /// (no RPC response) stay observable; `abort`/`commit` failures
    /// are also observable via their RPC responses (`abort` error,
    /// `commit` ok + `staging_cleanup_error`). Retries are explicit
    /// client `art_abort` (bounded, no background workers).
    pub fn staging_cleanup_failed(&self) -> u64 {
        self.staging_cleanup_failed.load(Ordering::SeqCst)
    }

    /// Test-only owned-staging unlink failpoint: the next `n` calls to
    /// [`ArtifactStore::unlink_staging_owned`] fail with an injected
    /// error (counted in `staging_cleanup_failed`) instead of
    /// attempting the real unlink. Production never sets this (always
    /// 0). Integration tests set it via
    /// `Server::set_artifact_unlink_failpoint_for_test` to prove
    /// observable, retryable, bounded cleanup without timing races or
    /// permission tricks that silently change under UID 0.
    pub fn set_unlink_failpoint_for_test(&self, n: u64) {
        self.unlink_fail_remaining.store(n, Ordering::SeqCst);
    }

    /// Current staging admission bounds (fast copy-out, no IO).
    /// Production always reads [`StagingLimits::default`]; tests shrink
    /// via [`ArtifactStore::set_staging_limits_for_test`].
    pub fn staging_limits(&self) -> StagingLimits {
        *self.staging_limits.lock().unwrap()
    }

    /// Test hook: replace the staging admission bounds (deterministic
    /// tiny-limit tests). Existing reservations are grandfathered (a
    /// shrink never pops live uploads); the new bounds gate subsequent
    /// `init_upload` admissions. Production never calls this.
    pub fn set_staging_limits_for_test(&self, limits: StagingLimits) {
        *self.staging_limits.lock().unwrap() = limits;
    }

    /// Test hook: live staging reservation `(upload count, declared
    /// bytes)` across active plus retained cleanup-pending uploads
    /// (fast map read, no IO). Production has no reader; wire tests
    /// assert admission/denial behaviorally instead.
    pub fn staging_reserved_for_test(&self) -> (u64, u64) {
        let st = self.uploads.lock().unwrap();
        (st.global_count, st.global_bytes)
    }

    /// Unlink one owned staging file (caller holds the per-upload lock,
    /// no global locks; see wire `disconnect`/`art_commit`/`art_abort`).
    /// Failpoint first (deterministic tests, no IO): if
    /// `unlink_fail_remaining > 0`, claims one failure atomically,
    /// bumps `staging_cleanup_failed`, and returns
    /// `"staging cleanup failed: injected unlink failure"` without
    /// touching the filesystem. Otherwise attempts the real
    /// `remove_file`: `Ok` and `NotFound` (already gone via concurrent
    /// success or external sweep; goal achieved) succeed without
    /// counting; any other IO error bumps `staging_cleanup_failed` and
    /// returns `"staging cleanup failed: {e}"` (caller retains the
    /// upload for explicit `art_abort` retry and reports observably:
    /// `abort` error, `commit` ok + `staging_cleanup_error`,
    /// `disconnect` retained + counter; never silently presents failed
    /// physical cleanup as complete, never uncharges or double-charges
    /// after durable WAL success).
    pub fn unlink_staging_owned(&self, path: &Path) -> Result<(), String> {
        loop {
            let cur = self.unlink_fail_remaining.load(Ordering::SeqCst);
            if cur == 0 {
                break;
            }
            match self.unlink_fail_remaining.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.staging_cleanup_failed.fetch_add(1, Ordering::SeqCst);
                    return Err("staging cleanup failed: injected unlink failure".to_string());
                }
                Err(_) => continue,
            }
        }
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => {
                self.staging_cleanup_failed.fetch_add(1, Ordering::SeqCst);
                Err(format!("staging cleanup failed: {e}"))
            }
        }
    }

    /// Seed one replayed `art_own` charge (boot only, before serving).
    /// Saturates on overflow (fail-open cap would undercount; saturating
    /// keeps the denial gate conservative: capped usage still denies).
    pub fn restore_usage(&self, agent: &str, size: u64) {
        let mut usage = self.usage.lock().unwrap();
        let entry = usage.entry(agent.to_string()).or_insert(0);
        *entry = entry.saturating_add(size);
    }

    /// Reservation charge: check quota and add `size` atomically under
    /// the usage lock (no IO while held). On deny (including `u64`
    /// overflow in EVERY mode, even Unlimited), bumps `quota_denied`,
    /// leaves usage unchanged (no partial charge, no rollback needed),
    /// and returns `"artifact quota exceeded"`; on allow, the charge
    /// stays until [`ArtifactStore::uncharge`] rolls it back
    /// (bytes/WAL failure, saturating) or the op commits (kept). No
    /// panic path: the second `checked_add` is defensive (unreachable
    /// unless `check_quota` logic drifts) and denies conservatively.
    pub fn try_charge(&self, agent: &str, size: u64, quota: Quota) -> Result<(), String> {
        let mut usage = self.usage.lock().unwrap();
        let current = *usage.get(agent).unwrap_or(&0);
        if check_quota(current, size, quota).is_err() {
            drop(usage);
            self.inc_quota_denied();
            return Err("artifact quota exceeded".to_string());
        }
        let Some(next) = current.checked_add(size) else {
            drop(usage);
            self.inc_quota_denied();
            return Err("artifact quota exceeded".to_string());
        };
        usage.insert(agent.to_string(), next);
        Ok(())
    }

    /// Roll back a reservation (bytes/WAL failure path). Saturates at
    /// zero (never panics on concurrent accounting drift).
    pub fn uncharge(&self, agent: &str, size: u64) {
        let mut usage = self.usage.lock().unwrap();
        let current = *usage.get(agent).unwrap_or(&0);
        usage.insert(agent.to_string(), current.saturating_sub(size));
    }

    /// Advisory pre-check without charging (for `art_init`, which
    /// reserves nothing until commit). Bumps `quota_denied` on deny.
    pub fn check_available(&self, agent: &str, size: u64, quota: Quota) -> Result<(), String> {
        let current = self.usage_of(agent);
        if check_quota(current, size, quota).is_err() {
            self.inc_quota_denied();
            return Err("artifact quota exceeded".to_string());
        }
        Ok(())
    }

    /// Committed object path (validates sha first; never builds from
    /// unvalidated input, so `..`/slash/staging names cannot escape).
    pub fn object_path(&self, sha: &str) -> Result<PathBuf, String> {
        if !is_valid_sha(sha) {
            return Err("artifact not found".to_string());
        }
        Ok(self.dir.join(sha))
    }

    /// Staging path for a server-generated id (validates hex16).
    fn staging_path(&self, prefix: &str, id: &str) -> Result<PathBuf, String> {
        if !is_valid_upload_id(id) {
            return Err("stage failed: bad staging id".to_string());
        }
        Ok(self.dir.join(format!("{prefix}{id}")))
    }

    /// Generate a fresh staging id (`/dev/urandom` 64-bit hex, like
    /// `crate::tokens::secure_random_hex`; retries on collision).
    pub fn fresh_id() -> Result<String, String> {
        crate::tokens::secure_random_hex(8).map_err(|e| format!("stage failed: {e}"))
    }

    /// Fsync a directory (durability for rename/link commits).
    fn fsync_dir(dir: &Path) -> Result<(), String> {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("commit failed: dir fsync: {e}"))
    }

    /// Validate `final_path` as the expected content-addressed object:
    /// regular file, size equals `expected_size`, streaming content
    /// hash equals `expected_sha` (tampering repair, not blind dedup).
    /// Opens one handle, checks `is_file` + length, then hashes that
    /// same handle (bounded to `ART_MAX`, 64 KiB blocks). `NotFound`
    /// on open is `Missing` (proceed to publish); any other open,
    /// metadata, type, size, or content mismatch is `Invalid`
    /// (repair or fail closed, never dedup blindly). Preserves good
    /// objects (never deletes here); callers decide repair vs error.
    fn validate_existing(
        final_path: &Path,
        expected_sha: &str,
        expected_size: u64,
    ) -> Validated {
        use std::io::Read;
        let mut f = match std::fs::File::open(final_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Validated::Missing
            }
            Err(_) => return Validated::Invalid,
        };
        let meta = match f.metadata() {
            Ok(m) => m,
            Err(_) => return Validated::Invalid,
        };
        if !meta.is_file() {
            return Validated::Invalid;
        }
        if meta.len() != expected_size {
            return Validated::Invalid;
        }
        let mut h = Sha256::new();
        let mut total: u64 = 0;
        let mut buf = [0u8; 65536];
        loop {
            let n = match f.read(&mut buf) {
                Ok(n) => n,
                Err(_) => return Validated::Invalid,
            };
            if n == 0 {
                break;
            }
            total = match total.checked_add(n as u64) {
                Some(t) => t,
                None => return Validated::Invalid,
            };
            if total > ART_MAX {
                return Validated::Invalid;
            }
            h.update(&buf[..n]);
        }
        if total != expected_size {
            return Validated::Invalid;
        }
        if hex32(h.finalize()) != expected_sha {
            return Validated::Invalid;
        }
        Validated::Valid(f)
    }

    /// Establish dedup durability on an already-validated handle: file
    /// `sync_all` (data barrier) then directory `sync_all` (entry
    /// barrier), in that order, before WAL success. Failpoint checks
    /// run before each barrier so ordering tests observe file-first:
    /// `DEDUP_FILE` fails before any sync, `DEDUP_DIR` fails after
    /// file sync but before dir sync. Errors leave `final` untouched
    /// (good object preserved, retry re-validates).
    fn fsync_validated(
        &self,
        f: &std::fs::File,
        failpoint: u8,
    ) -> Result<(), String> {
        if failpoint == ART_FAIL_DEDUP_FILE_FSYNC {
            return Err("commit failed: dedup fsync".to_string());
        }
        f.sync_all()
            .map_err(|e| format!("commit failed: dedup fsync: {e}"))?;
        if failpoint == ART_FAIL_DEDUP_DIR_FSYNC {
            return Err("commit failed: dir fsync".to_string());
        }
        Self::fsync_dir(&self.dir)
    }

    /// Durably store `raw` as its sha256 object. Validates any
    /// existing object (regular file, size, streaming content hash;
    /// never blind metadata existence): valid dedups only after file +
    /// directory fsync barriers (every acked put, including retry/dedup,
    /// is durable before WAL success); missing or tampered (wrong
    /// size/content regular file) proceeds to private `.put-*` staging
    /// (`0600`, write, fsync), atomic rename (overwrites identical or
    /// repairs tampered bytes; fails closed on directories, preserving
    /// them), dir fsync. No quota/usage/WAL here (caller reserves,
    /// logs, then keeps or rolls back). Returns `(sha, dedup)`.
    pub fn put_bytes_durable(&self, raw: &[u8]) -> Result<(String, bool), String> {
        Self::put_bytes_durable_with_failpoint(self, raw, ART_FAIL_NONE)
    }

    /// Test hook: `put_bytes_durable` with durability failpoint.
    /// Production always passes [`ART_FAIL_NONE`]; tests pass dedup or
    /// put dir-fsync failpoints to prove barrier ordering (file before
    /// dir) and error propagation (no ack without durability, good
    /// objects preserved, retry re-validates).
    pub fn put_bytes_durable_with_failpoint(
        &self,
        raw: &[u8],
        failpoint: u8,
    ) -> Result<(String, bool), String> {
        let sha = sha256_hex(raw);
        let final_path = self.object_path(&sha)?;
        match Self::validate_existing(&final_path, &sha, raw.len() as u64) {
            Validated::Valid(f) => {
                self.fsync_validated(&f, failpoint)?;
                return Ok((sha, true));
            }
            Validated::Missing => {}
            Validated::Invalid => {
                // Fall through to repair attempt (staging + rename).
                // Directories fail closed at rename (preserved, Err);
                // wrong-size/content regular files are overwritten.
            }
        }
        let id = Self::fresh_id()?;
        let staging = self.staging_path(STAGING_PUT_PREFIX, &id)?;
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&staging).map_err(|e| format!("stage failed: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            use std::io::Write;
            f.write_all(raw).map_err(|e| {
                let _ = std::fs::remove_file(&staging);
                format!("stage failed: {e}")
            })?;
            f.sync_all().map_err(|e| {
                let _ = std::fs::remove_file(&staging);
                format!("stage failed: fsync: {e}")
            })?;
        }
        // Concurrent identical puts may have published first; rename
        // overwrites identical bytes atomically (content-addressed, so
        // no loss). Tampered files are repaired here. Directories fail
        // (preserved). Dedup is reported from pre-write validation, not
        // from this rename.
        if let Err(e) = std::fs::rename(&staging, &final_path) {
            let _ = std::fs::remove_file(&staging);
            return Err(format!("commit failed: {e}"));
        }
        if failpoint == ART_FAIL_PUT_DIR_FSYNC {
            // Bytes visible but entry possibly non-durable; report
            // failure so caller rolls back and retry dedups durably.
            // Never delete `final` (concurrent put may own it now).
            return Err("commit failed: dir fsync".to_string());
        }
        if let Err(e) = Self::fsync_dir(&self.dir) {
            // Bytes are visible but the directory entry may not be
            // durable; report failure so the caller rolls back the
            // charge and the retry dedups. Never delete `final` here
            // (a concurrent put may own it now).
            return Err(e);
        }
        Ok((sha, false))
    }

    /// Read one committed object on a single opened regular-file
    /// handle with an actual `ART_MAX + 1` consumption bound (no
    /// separate path preflight + `read` TOCTOU, no unbounded
    /// allocation). Opens, checks `is_file` on that handle, then
    /// `take(ART_MAX + 1).read_to_end` (bounded even if the file grows
    /// mid-read; no `with_capacity(meta.len())` on tampered lengths).
    /// More than `ART_MAX` bytes fails as not-found (tampered oversize,
    /// never OOM). Strict hex ids only (no staging exposure).
    pub fn get_bytes(&self, sha: &str) -> Result<Vec<u8>, String> {
        use std::io::Read;
        let path = self.object_path(sha)?;
        let f = std::fs::File::open(&path).map_err(|_| "artifact not found".to_string())?;
        let meta = f.metadata().map_err(|_| "artifact not found".to_string())?;
        if !meta.is_file() {
            return Err("artifact not found".to_string());
        }
        let limit = ART_MAX.saturating_add(1);
        let mut buf = Vec::new();
        f.take(limit)
            .read_to_end(&mut buf)
            .map_err(|_| "artifact not found".to_string())?;
        if buf.len() as u64 > ART_MAX {
            return Err("artifact not found".to_string());
        }
        Ok(buf)
    }

    /// Stat one committed object (size only, no bytes) on a single
    /// opened handle (same open-then-metadata identity as
    /// [`ArtifactStore::get_bytes`] and [`ArtifactStore::range`]; no
    /// path preflight TOCTOU). Strict hex ids only.
    pub fn stat(&self, sha: &str) -> Result<u64, String> {
        let path = self.object_path(sha)?;
        let f = std::fs::File::open(&path).map_err(|_| "artifact not found".to_string())?;
        let meta = f.metadata().map_err(|_| "artifact not found".to_string())?;
        if !meta.is_file() {
            return Err("artifact not found".to_string());
        }
        Ok(meta.len())
    }

    /// Bounded range read: `off <= size`, `len <= CHUNK_MAX`, clamped
    /// to `size - off`. Returns `(bytes, size)`.
    pub fn range(&self, sha: &str, off: u64, len: u64) -> Result<(Vec<u8>, u64), String> {
        use std::io::{Read, Seek};
        if len > CHUNK_MAX {
            return Err("bad range".to_string());
        }
        let path = self.object_path(sha)?;
        let mut f = std::fs::File::open(&path).map_err(|_| "artifact not found".to_string())?;
        let meta = f.metadata().map_err(|_| "artifact not found".to_string())?;
        if !meta.is_file() {
            return Err("artifact not found".to_string());
        }
        let size = meta.len();
        if off > size {
            return Err("bad range".to_string());
        }
        let take = len.min(size - off) as usize;
        f.seek(std::io::SeekFrom::Start(off))
            .map_err(|_| "artifact not found".to_string())?;
        let mut buf = vec![0u8; take];
        f.read_exact(&mut buf).map_err(|_| "artifact not found".to_string())?;
        Ok((buf, size))
    }

    /// Streaming sha256 of a staging file plus its size (bounded to
    /// `ART_MAX`; 64 KiB blocks like legacy `art_commit`). Uses
    /// maintained `sha2` via [`Sha256`] adapter.
    pub fn hash_file(path: &Path, max: u64) -> Result<(String, u64), String> {
        use std::io::Read;
        let mut f = std::fs::File::open(path).map_err(|e| format!("commit failed: {e}"))?;
        let mut h = Sha256::new();
        let mut total: u64 = 0;
        let mut buf = [0u8; 65536];
        loop {
            let n = f.read(&mut buf).map_err(|e| format!("commit failed: {e}"))?;
            if n == 0 {
                break;
            }
            total = total.checked_add(n as u64).ok_or_else(|| "commit failed: too large".to_string())?;
            if total > max {
                return Err("commit failed: too large".to_string());
            }
            h.update(&buf[..n]);
        }
        let sum = h.finalize();
        Ok((hex32(sum), total))
    }

    /// Publish a staged upload file to its sha object. Validates any
    /// existing object (regular file, size, streaming content hash;
    /// never blind metadata existence): valid dedups only after file +
    /// directory fsync barriers (every acked commit, including
    /// retry/dedup and `AlreadyExists` races, is durable before WAL
    /// success); missing proceeds to link; tampered regular files are
    /// repaired via private temp + atomic rename (never remove-first,
    /// final never absent due to repair, concurrent valid preserved);
    /// directories fail closed (preserved, never recursively deleted).
    /// Otherwise fsync staging, hardlink staging to final (same inode,
    /// no copy), dir fsync. Staging is kept in all cases; the caller
    /// unlinks it only after the WAL `art_own` succeeds, so a WAL
    /// failure leaves staging for a clean retry (hash again, validate
    /// again). Caller holds the per-upload lock (no global locks).
    /// Callers must have verified staging content hashes to `sha`
    /// (wire `art_commit` does); repair replaces same-sha bytes only.
    pub fn publish_staged(&self, staging: &Path, sha: &str) -> Result<bool, String> {
        self.publish_staged_with_failpoint(staging, sha, ART_FAIL_NONE)
    }

    /// Test hook: `publish_staged` with durability failpoint.
    /// Production always passes [`ART_FAIL_NONE`]; tests pass dedup or
    /// publish dir-fsync failpoints to prove barrier ordering and
    /// `AlreadyExists` race durability (no ack without validation +
    /// fsyncs, good objects preserved).
    pub fn publish_staged_with_failpoint(
        &self,
        staging: &Path,
        sha: &str,
        failpoint: u8,
    ) -> Result<bool, String> {
        let final_path = self.object_path(sha)?;
        let staging_file =
            std::fs::File::open(staging).map_err(|e| format!("commit failed: {e}"))?;
        let staging_meta = staging_file
            .metadata()
            .map_err(|e| format!("commit failed: {e}"))?;
        if !staging_meta.is_file() {
            return Err("commit failed: staging not a file".to_string());
        }
        let staging_len = staging_meta.len();
        match Self::validate_existing(&final_path, sha, staging_len) {
            Validated::Valid(f) => {
                drop(staging_file);
                self.fsync_validated(&f, failpoint)?;
                return Ok(true);
            }
            Validated::Missing => {}
            Validated::Invalid => {
                // Atomic repair: private temp + rename, never remove-first.
                // Final is never absent due to our repair; a later error
                // leaves the previous name present (tampered or concurrent
                // valid), never deleted. Re-validation best-effort avoids
                // overwriting a concurrent valid that won before the check
                // (reports dedup); it cannot prevent a valid winning after
                // the check, but overwriting with identical same-sha bytes
                // via atomic rename preserves content/availability.
                staging_file
                    .sync_all()
                    .map_err(|e| format!("commit failed: {e}"))?;
                drop(staging_file);
                return self.repair_invalid_via_rename(
                    staging,
                    sha,
                    &final_path,
                    staging_len,
                    failpoint,
                );
            }
        }
        staging_file
            .sync_all()
            .map_err(|e| format!("commit failed: {e}"))?;
        drop(staging_file);
        match std::fs::hard_link(staging, &final_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                match Self::validate_existing(&final_path, sha, staging_len) {
                    Validated::Valid(f) => {
                        self.fsync_validated(&f, failpoint)?;
                        return Ok(true);
                    }
                    _ => {
                        return Err(
                            "commit failed: concurrent publish raced invalid".to_string()
                        );
                    }
                }
            }
            Err(e) => return Err(format!("commit failed: {e}")),
        }
        if failpoint == ART_FAIL_PUBLISH_DIR_FSYNC {
            return Err("commit failed: dir fsync".to_string());
        }
        Self::fsync_dir(&self.dir)?;
        Ok(false)
    }

    /// Repair a tampered `final_path` without removing it first: link
    /// staging to a private `.put-*` temp (same inode, no copy), then
    /// atomic rename temp over final (overwrites tampered regular files,
    /// fails closed on directories). Re-validates before rename as a
    /// best-effort to report a concurrent legitimate repair as dedup
    /// (discards temp, no overwrite); revalidation cannot guarantee no
    /// concurrent identical inode wins after the check, but overwriting
    /// with identical same-sha content via atomic rename preserves
    /// content/availability (same bytes, inode may change). Staging is
    /// always kept (caller unlinks after WAL ok); temp is cleaned on
    /// every failure path (boot also sweeps `.put-*`). File barrier
    /// (staging sync) already established by the caller; this
    /// establishes rename then dir fsync before WAL success.
    fn repair_invalid_via_rename(
        &self,
        staging: &Path,
        sha: &str,
        final_path: &Path,
        staging_len: u64,
        failpoint: u8,
    ) -> Result<bool, String> {
        let temp = {
            let mut last_err: Option<String> = None;
            let mut found: Option<PathBuf> = None;
            for _ in 0..8 {
                let id = Self::fresh_id()?;
                let candidate = self.staging_path(STAGING_PUT_PREFIX, &id)?;
                match std::fs::hard_link(staging, &candidate) {
                    Ok(()) => {
                        found = Some(candidate);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => {
                        last_err = Some(format!("commit failed: {e}"));
                        break;
                    }
                }
            }
            match (found, last_err) {
                (Some(p), _) => p,
                (None, Some(e)) => return Err(e),
                (None, None) => return Err("commit failed: temp collision".to_string()),
            }
        };
        // Concurrent legitimate repair won between our first validation and
        // temp creation: preserve it as dedup, discard temp.
        match Self::validate_existing(final_path, sha, staging_len) {
            Validated::Valid(f) => {
                let _ = std::fs::remove_file(&temp);
                self.fsync_validated(&f, failpoint)?;
                return Ok(true);
            }
            Validated::Missing | Validated::Invalid => {}
        }
        if let Err(e) = std::fs::rename(&temp, final_path) {
            let _ = std::fs::remove_file(&temp);
            // Rename failed (directory, permission, etc.): a concurrent
            // valid that won after our second validation is reported as
            // dedup when present; otherwise fail closed with final still
            // present (never absent). A concurrent valid winning after
            // the check but before a successful rename is overwritten
            // with identical same-sha bytes (atomic rename preserves
            // content/availability); revalidation cannot prevent that
            // post-check race.
            match Self::validate_existing(final_path, sha, staging_len) {
                Validated::Valid(f) => {
                    self.fsync_validated(&f, failpoint)?;
                    return Ok(true);
                }
                _ => return Err(format!("commit failed: {e}")),
            }
        }
        if failpoint == ART_FAIL_PUBLISH_DIR_FSYNC {
            // Bytes repaired and visible but entry possibly non-durable;
            // report failure so caller rolls back and retry dedups.
            return Err("commit failed: dir fsync".to_string());
        }
        Self::fsync_dir(&self.dir)?;
        Ok(false)
    }

    /// Create a pending upload: validates `1 <= size <= ART_MAX` and
    /// sha shape (fail fast, no locks), admits against
    /// [`StagingLimits`] (global/per-owner count and declared bytes;
    /// denials reserve nothing and return [`STAGING_COUNT_ERROR`] or
    /// [`STAGING_BYTES_ERROR`]), reserves atomically with the map
    /// insert under the uploads lock (no IO while held), then creates
    /// private `.up-*` staging outside the lock. Staging-creation
    /// failure marks the upload terminal before rolling the reservation
    /// back via [`ArtifactStore::pop_upload`]; `AlreadyExists` retries
    /// with a fresh id without unlinking the pre-existing file.
    /// Returns the opaque upload id. No quota charge here (advisory
    /// pre-check by caller); commit reserves. The per-upload mutex is
    /// acquired BEFORE map insertion and held through creation. Chunk,
    /// commit, abort and disconnect therefore cannot act on a partially
    /// initialized upload. Failed cleanup after a successful creation
    /// follows the ordinary retained-owner/reservation path in the wire
    /// handlers; initialization needs no separate unowned-file cleanup.
    pub fn init_upload(
        &self,
        agent: &str,
        size: u64,
        sha: Option<String>,
    ) -> Result<String, String> {
        self.init_upload_observed(agent, size, sha, |_, _, _| {})
    }

    fn init_upload_observed(
        &self,
        agent: &str,
        size: u64,
        sha: Option<String>,
        mut observe: impl FnMut(&str, &Path, UploadInitPhase),
    ) -> Result<String, String> {
        if size == 0 || size > ART_MAX {
            return Err(format!("bad size (1..{ART_MAX})"));
        }
        if let Some(want) = &sha {
            if !is_valid_sha(want) {
                return Err("sha mismatch".to_string());
            }
        }
        // Copy bounds out before the uploads lock (never nested).
        let limits = self.staging_limits();
        for _ in 0..8 {
            let id = Self::fresh_id()?;
            let staging = self.staging_path(STAGING_UP_PREFIX, &id)?;
            let handle = Arc::new(Mutex::new(PendingUpload {
                agent: agent.to_string(),
                size,
                sha: sha.clone(),
                path: staging.clone(),
                received: 0,
                state: UploadState::Active,
            }));
            // This handle is still private: locking before publication
            // prevents cancellation from treating not-yet-created staging
            // as already cleaned. No global lock spans creation.
            let mut up = handle.lock().unwrap();
            // Atomic admission check + count/byte reservation + map
            // insert (no IO while the uploads lock is held). Denials
            // take nothing; id collision retries with a fresh id.
            {
                let mut st = self.uploads.lock().unwrap();
                if st.map.contains_key(&id) {
                    continue;
                }
                if st.global_count >= limits.max_uploads_global {
                    return Err(STAGING_COUNT_ERROR.to_string());
                }
                let (ocount, obytes) = st.per_owner.get(agent).copied().unwrap_or((0, 0));
                if ocount >= limits.max_uploads_per_owner {
                    return Err(STAGING_COUNT_ERROR.to_string());
                }
                let (Some(next_global), Some(next_owner)) =
                    (st.global_bytes.checked_add(size), obytes.checked_add(size))
                else {
                    return Err(STAGING_BYTES_ERROR.to_string());
                };
                if next_global > limits.max_declared_bytes_global
                    || next_owner > limits.max_declared_bytes_per_owner
                {
                    return Err(STAGING_BYTES_ERROR.to_string());
                }
                // Reserve: counts cannot overflow (each is `<` its `u64`
                // max here, so `+ 1` fits); bytes use the checked sums.
                st.global_count += 1;
                st.global_bytes = next_global;
                st.per_owner
                    .insert(agent.to_string(), (ocount + 1, next_owner));
                st.map.insert(id.clone(), Arc::clone(&handle));
            }
            observe(&id, &staging, UploadInitPhase::BeforeCreate);
            // Create staging OUTSIDE the uploads lock, rolling the
            // reservation back on any failure (no leaked reservation,
            // no orphan file; `AlreadyExists` retries with a fresh id).
            {
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                match opts.open(&staging) {
                    Ok(f) => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
                        }
                        drop(f);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        // This attempt never owned the existing file. A
                        // waiting operation must see terminal state and
                        // must not unlink another attempt's file.
                        up.state = UploadState::Aborted;
                        drop(up);
                        self.pop_upload(&id);
                        continue;
                    }
                    Err(e) => {
                        up.state = UploadState::Aborted;
                        drop(up);
                        self.pop_upload(&id);
                        return Err(format!("stage failed: {e}"));
                    }
                }
            }
            observe(&id, &staging, UploadInitPhase::AfterCreate);
            drop(up);
            return Ok(id);
        }
        Err("stage failed: id collision".to_string())
    }

    /// Clone one upload handle (fast map lookup, no IO).
    pub fn lookup_upload(&self, uid: &str) -> Option<Arc<Mutex<PendingUpload>>> {
        self.uploads.lock().unwrap().map.get(uid).cloned()
    }

    /// Pop one upload from the map AND release its staging reservation
    /// atomically (fast; no IO). Callers pop only after setting terminal
    /// state under the per-upload lock and confirming physical cleanup
    /// (unlink success or already-gone); retained cleanup failures are
    /// never popped, so they keep holding their reservation until an
    /// explicit `art_abort` retry (or a bounded disconnect attempt)
    /// confirms cleanup. Releasing never touches durable committed
    /// usage (no uncharge, no recommit). Returns the popped handle, or
    /// `None` when absent (a double pop releases nothing). Lookup releases
    /// the global lock before waiting for the per-upload mutex; removal
    /// then briefly takes the global lock with identity revalidation. No
    /// global lock can be held waiting for another upload's file IO.
    /// Callers drop their per-upload guard before calling this method.
    pub fn pop_upload(&self, uid: &str) -> Option<Arc<Mutex<PendingUpload>>> {
        let handle = self.lookup_upload(uid)?;
        let up = handle.lock().unwrap();
        let (agent, size) = (up.agent.clone(), up.size);
        let mut st = self.uploads.lock().unwrap();
        if !Arc::ptr_eq(st.map.get(uid)?, &handle) {
            return None;
        }
        st.map.remove(uid);
        // Exact release (`saturating_*` only as unreachable defense:
        // every map entry holds exactly one reservation, and only the
        // popper removes it, so the counters always cover this entry).
        st.global_count = st.global_count.saturating_sub(1);
        st.global_bytes = st.global_bytes.saturating_sub(size);
        if let Some((count, bytes)) = st.per_owner.get(&agent).copied() {
            let count = count.saturating_sub(1);
            let bytes = bytes.saturating_sub(size);
            if count == 0 {
                st.per_owner.remove(&agent);
            } else {
                st.per_owner.insert(agent, (count, bytes));
            }
        }
        drop(st);
        drop(up);
        Some(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_store(tag: &str) -> (ArtifactStore, PathBuf) {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut dir = std::env::temp_dir();
        dir.push(format!("agent-bus-artifacts-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = ArtifactStore::new(dir.clone()).expect("fresh store");
        (store, dir)
    }

    fn temp_store_with_limits(tag: &str, limits: StagingLimits) -> (ArtifactStore, PathBuf) {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut dir = std::env::temp_dir();
        dir.push(format!("agent-bus-artifacts-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = ArtifactStore::new_with_limits(dir.clone(), limits).expect("fresh store");
        (store, dir)
    }

    #[test]
    fn sha256_vectors_match_hashlib() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // Streaming equals one-shot across block boundaries (55/56/57/64/65 bytes).
        for len in [0usize, 1, 55, 56, 57, 63, 64, 65, 128, 1000] {
            let data = vec![0x61u8; len];
            let mut h = Sha256::new();
            for chunk in data.chunks(7) {
                h.update(chunk);
            }
            let sum = h.finalize();
            let mut hex = String::new();
            for b in sum {
                hex.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                hex.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
            }
            assert_eq!(hex, sha256_hex(&data), "len={len}");
        }
    }

    #[test]
    fn base64_roundtrip_and_rejections() {
        for raw in [b"".as_slice(), b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let enc = base64_encode(raw);
            assert_eq!(base64_decode(&enc).unwrap(), raw, "{enc}");
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(base64_decode("").unwrap(), b"");
        for bad in ["A", "ABC", "AB=C", "A===", "====", "AB CD", "AB\nCD", "AB*D", "ABCDE"] {
            assert_eq!(base64_decode(bad), Err("bad base64".to_string()), "{bad:?}");
        }
        // Padding only at the very end.
        assert!(base64_decode("ABCD").is_ok());
        assert_eq!(base64_decode("AB=="), Ok(vec![0x00]));
        assert_eq!(base64_decode("ABC="), Ok(vec![0x00, 0x10]));
    }

    #[test]
    fn quota_parsing_and_checked_gate() {
        use serde_json::json;
        assert_eq!(parse_quota(None), Quota::Unlimited);
        assert_eq!(parse_quota(Some(&json!(null))), Quota::Unlimited);
        assert_eq!(parse_quota(Some(&json!(10))), Quota::Limited(10));
        assert_eq!(parse_quota(Some(&json!(0))), Quota::Limited(0));
        assert_eq!(parse_quota(Some(&json!(-3))), Quota::Limited(0));
        assert_eq!(parse_quota(Some(&json!(3.7))), Quota::Limited(3));
        assert_eq!(parse_quota(Some(&json!("10"))), Quota::Malformed);
        assert_eq!(parse_quota(Some(&json!(true))), Quota::Malformed);
        assert_eq!(parse_quota(Some(&json!([1]))), Quota::Malformed);
        assert!(check_quota(0, 5, Quota::Unlimited).is_ok());
        assert!(check_quota(5, 5, Quota::Limited(10)).is_ok());
        assert_eq!(
            check_quota(6, 5, Quota::Limited(10)),
            Err("artifact quota exceeded".to_string())
        );
        assert_eq!(
            check_quota(u64::MAX, 1, Quota::Limited(u64::MAX)),
            Err("artifact quota exceeded".to_string())
        );
        assert_eq!(
            check_quota(0, 0, Quota::Malformed),
            Err("artifact quota exceeded".to_string())
        );
        assert!(is_valid_sha(&sha256_hex(b"x")));
        assert!(!is_valid_sha(""));
        assert!(!is_valid_sha(".up-abc"));
        assert!(!is_valid_sha("ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"));
        assert!(is_valid_upload_id("0123456789abcdef"));
        assert!(!is_valid_upload_id("../evil"));
    }

    #[test]
    fn store_put_get_stat_range_dedup() {
        let (store, dir) = temp_store("basic");
        let raw = b"native artifacts";
        let (sha, dedup) = store.put_bytes_durable(raw).unwrap();
        assert!(!dedup);
        assert_eq!(sha, sha256_hex(raw));
        let (sha2, dedup2) = store.put_bytes_durable(raw).unwrap();
        assert!(dedup2);
        assert_eq!(sha, sha2);
        assert_eq!(store.get_bytes(&sha).unwrap(), raw);
        assert_eq!(store.stat(&sha).unwrap(), raw.len() as u64);
        let (head, size) = store.range(&sha, 0, 6).unwrap();
        assert_eq!(head, b"native");
        assert_eq!(size, raw.len() as u64);
        let (tail, _) = store.range(&sha, 7, 100).unwrap();
        assert_eq!(tail, b"artifacts");
        assert_eq!(store.range(&sha, 0, CHUNK_MAX + 1), Err("bad range".to_string()));
        assert_eq!(store.range(&sha, size + 1, 1), Err("bad range".to_string()));
        assert_eq!(store.get_bytes("nope"), Err("artifact not found".to_string()));
        assert_eq!(
            store.get_bytes(".up-0123456789abcdef"),
            Err("artifact not found".to_string())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_reservation_rolls_back_on_failure() {
        let (store, dir) = temp_store("quota");
        assert!(store.try_charge("a", 5, Quota::Limited(10)).is_ok());
        assert_eq!(store.usage_of("a"), 5);
        assert_eq!(
            store.try_charge("a", 6, Quota::Limited(10)),
            Err("artifact quota exceeded".to_string())
        );
        assert_eq!(store.usage_of("a"), 5);
        assert_eq!(store.quota_denied(), 1);
        store.uncharge("a", 5);
        assert_eq!(store.usage_of("a"), 0);
        store.restore_usage("b", 7);
        assert_eq!(store.usage_of("b"), 7);
        store.restore_usage("b", u64::MAX);
        assert_eq!(store.usage_of("b"), u64::MAX);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_init_validates_size_and_sha() {
        let (store, dir) = temp_store("init");
        assert!(store.init_upload("a", 0, None).is_err());
        assert!(store.init_upload("a", ART_MAX + 1, None).is_err());
        assert_eq!(
            store.init_upload("a", 10, Some("nothex".to_string())),
            Err("sha mismatch".to_string())
        );
        let uid = store.init_upload("a", 10, None).unwrap();
        assert!(is_valid_upload_id(&uid));
        assert!(store.lookup_upload(&uid).is_some());
        assert!(store.lookup_upload("nope").is_none());
        assert!(store.pop_upload(&uid).is_some());
        assert!(store.lookup_upload(&uid).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_boot_cleans_staging_but_keeps_objects() {
        let (store, dir) = temp_store("boot");
        let (sha, _) = store.put_bytes_durable(b"keep").unwrap();
        let stale = dir.join(".up-0123456789abcdef");
        std::fs::write(&stale, b"stale").unwrap();
        let stale2 = dir.join(".put-0123456789abcdef");
        std::fs::write(&stale2, b"stale").unwrap();
        drop(store);
        let store2 = ArtifactStore::new(dir.clone()).unwrap();
        assert!(!stale.exists());
        assert!(!stale2.exists());
        assert_eq!(store2.get_bytes(&sha).unwrap(), b"keep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quota_unlimited_overflow_denies_no_panic() {
        // Every mode checks usage+size overflow, including Unlimited.
        assert!(check_quota(0, 0, Quota::Unlimited).is_ok());
        assert!(check_quota(0, 5, Quota::Unlimited).is_ok());
        assert!(check_quota(u64::MAX, 0, Quota::Unlimited).is_ok());
        assert_eq!(
            check_quota(u64::MAX, 1, Quota::Unlimited),
            Err("artifact quota exceeded".to_string())
        );
        assert_eq!(
            check_quota(u64::MAX - 1, 2, Quota::Unlimited),
            Err("artifact quota exceeded".to_string())
        );
        // Finite empty + overflow still correct.
        assert!(check_quota(10, 0, Quota::Limited(10)).is_ok());
        assert_eq!(
            check_quota(u64::MAX, 1, Quota::Limited(u64::MAX)),
            Err("artifact quota exceeded".to_string())
        );
        // try_charge never panics, denies conservatively, bumps counter,
        // leaves usage unchanged (no partial charge to roll back).
        let (store, dir) = temp_store("quota-overflow");
        store.restore_usage("sat", u64::MAX);
        assert_eq!(store.usage_of("sat"), u64::MAX);
        assert_eq!(
            store.try_charge("sat", 1, Quota::Unlimited),
            Err("artifact quota exceeded".to_string())
        );
        assert_eq!(store.usage_of("sat"), u64::MAX);
        assert_eq!(store.quota_denied(), 1);
        // Empty at saturation allows (MAX + 0 == MAX), no counter bump.
        assert!(store.try_charge("sat", 0, Quota::Unlimited).is_ok());
        assert_eq!(store.usage_of("sat"), u64::MAX);
        assert_eq!(store.quota_denied(), 1);
        // Advisory pre-check also denies overflow and bumps.
        assert_eq!(
            store.check_available("sat", 1, Quota::Unlimited),
            Err("artifact quota exceeded".to_string())
        );
        assert_eq!(store.quota_denied(), 2);
        // Ordinary empty + finite behavior unchanged.
        assert!(store.try_charge("e", 0, Quota::Unlimited).is_ok());
        assert_eq!(store.usage_of("e"), 0);
        assert!(store.try_charge("f", 5, Quota::Limited(10)).is_ok());
        assert_eq!(store.usage_of("f"), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dedup_validates_and_barriers_fail_closed() {
        let (store, dir) = temp_store("dedup-durability");
        let raw = b"dedup durability";
        let (sha, dedup) = store.put_bytes_durable(raw).unwrap();
        assert!(!dedup);
        // Clean dedup establishes barriers and reports true.
        let (sha2, dedup2) = store
            .put_bytes_durable_with_failpoint(raw, ART_FAIL_NONE)
            .unwrap();
        assert!(dedup2);
        assert_eq!(sha, sha2);
        // File barrier fails first: no ack, good object preserved.
        assert_eq!(
            store.put_bytes_durable_with_failpoint(raw, ART_FAIL_DEDUP_FILE_FSYNC),
            Err("commit failed: dedup fsync".to_string())
        );
        assert_eq!(store.get_bytes(&sha).unwrap(), raw);
        // Dir barrier fails after file sync: no ack, preserved.
        assert_eq!(
            store.put_bytes_durable_with_failpoint(raw, ART_FAIL_DEDUP_DIR_FSYNC),
            Err("commit failed: dir fsync".to_string())
        );
        assert_eq!(store.get_bytes(&sha).unwrap(), raw);
        // Tampered same-size content repairs (not blind dedup).
        let final_path = store.object_path(&sha).unwrap();
        let mut bad = raw.to_vec();
        bad[0] ^= 0xff;
        std::fs::write(&final_path, &bad).unwrap();
        let (sha3, dedup3) = store.put_bytes_durable(raw).unwrap();
        assert!(!dedup3);
        assert_eq!(sha, sha3);
        assert_eq!(store.get_bytes(&sha).unwrap(), raw);
        // Tampered wrong-size repairs.
        std::fs::write(&final_path, b"short").unwrap();
        let (sha4, dedup4) = store.put_bytes_durable(raw).unwrap();
        assert!(!dedup4);
        assert_eq!(sha, sha4);
        assert_eq!(store.get_bytes(&sha).unwrap(), raw);
        // Directory at object path fails closed, preserved, never deleted.
        let raw2 = b"dir collision";
        let sha_dir = sha256_hex(raw2);
        let dir_path = store.object_path(&sha_dir).unwrap();
        std::fs::create_dir_all(&dir_path).unwrap();
        assert!(store.put_bytes_durable(raw2).is_err());
        assert!(dir_path.is_dir());
        let _ = std::fs::remove_dir_all(&dir_path);
        // New-put dir barrier failure leaves orphan bytes for retry dedup.
        let raw3 = b"orphan retry";
        assert_eq!(
            store.put_bytes_durable_with_failpoint(raw3, ART_FAIL_PUT_DIR_FSYNC),
            Err("commit failed: dir fsync".to_string())
        );
        let sha3b = sha256_hex(raw3);
        assert!(store.object_path(&sha3b).unwrap().exists());
        let (sha3c, dedup3c) = store.put_bytes_durable(raw3).unwrap();
        assert!(dedup3c);
        assert_eq!(sha3b, sha3c);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_staged_validates_and_barriers() {
        let (store, dir) = temp_store("publish-durability");
        let raw = b"publish me";
        let sha = sha256_hex(raw);
        let staging = dir.join(".up-0123456789abcd");
        std::fs::write(&staging, raw).unwrap();
        // First publish links, reports false.
        assert!(!store.publish_staged(&staging, &sha).unwrap());
        assert_eq!(store.get_bytes(&sha).unwrap(), raw);
        // Dedup barriers fail closed, preserved.
        assert_eq!(
            store.publish_staged_with_failpoint(&staging, &sha, ART_FAIL_DEDUP_FILE_FSYNC),
            Err("commit failed: dedup fsync".to_string())
        );
        assert_eq!(
            store.publish_staged_with_failpoint(&staging, &sha, ART_FAIL_DEDUP_DIR_FSYNC),
            Err("commit failed: dir fsync".to_string())
        );
        assert_eq!(store.get_bytes(&sha).unwrap(), raw);
        // Tampered final repairs via atomic temp + rename (staging kept,
        // final never removed first). Recreate staging as a separate inode
        // first: after the first hardlink publish, staging and final share
        // one inode, so a direct write to final would corrupt staging too.
        // Production unlinks staging after WAL ok (separate thereafter);
        // the test mirrors that by unlinking + recreating staging before
        // tamper.
        let final_path = store.object_path(&sha).unwrap();
        let _ = std::fs::remove_file(&staging);
        std::fs::write(&staging, raw).unwrap();
        std::fs::write(&final_path, b"tampered!!").unwrap();
        assert!(!store.publish_staged(&staging, &sha).unwrap());
        assert_eq!(store.get_bytes(&sha).unwrap(), raw);
        assert!(staging.exists());
        // Repair leaves no private temp behind (renamed, not leaked).
        let mut put_temps = 0;
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(STAGING_PUT_PREFIX) {
                put_temps += 1;
            }
        }
        assert_eq!(put_temps, 0, "repair temp must not leak");
        // Directory at final fails closed, preserved, staging kept, final
        // still present (never absent due to repair attempt).
        let raw_dir = b"publish dir collision";
        let sha_dir = sha256_hex(raw_dir);
        let dir_path = store.object_path(&sha_dir).unwrap();
        std::fs::create_dir_all(&dir_path).unwrap();
        let staging_dir = dir.join(".up-0123456789abcf");
        std::fs::write(&staging_dir, raw_dir).unwrap();
        assert!(store.publish_staged(&staging_dir, &sha_dir).is_err());
        assert!(dir_path.is_dir(), "dir preserved, never deleted");
        assert!(staging_dir.exists(), "staging kept for retry");
        assert!(dir_path.exists(), "final name still present after error");
        let _ = std::fs::remove_dir_all(&dir_path);
        let _ = std::fs::remove_file(&staging_dir);
        // Repair dir-barrier failure leaves repaired bytes for retry dedup
        // (final present and valid, staging kept).
        let _ = std::fs::remove_file(&staging);
        std::fs::write(&staging, raw).unwrap();
        std::fs::write(&final_path, b"tampered!!").unwrap();
        assert_eq!(
            store.publish_staged_with_failpoint(&staging, &sha, ART_FAIL_PUBLISH_DIR_FSYNC),
            Err("commit failed: dir fsync".to_string())
        );
        assert!(final_path.exists(), "failed repair leaves final present");
        assert_eq!(store.get_bytes(&sha).unwrap(), raw);
        assert!(staging.exists());
        assert!(store.publish_staged(&staging, &sha).unwrap());
        // New-publish dir barrier failure leaves link for retry dedup.
        let raw2 = b"publish orphan";
        let sha2 = sha256_hex(raw2);
        let staging2 = dir.join(".up-0123456789abce");
        std::fs::write(&staging2, raw2).unwrap();
        assert_eq!(
            store.publish_staged_with_failpoint(&staging2, &sha2, ART_FAIL_PUBLISH_DIR_FSYNC),
            Err("commit failed: dir fsync".to_string())
        );
        assert!(store.object_path(&sha2).unwrap().exists());
        assert!(store.publish_staged(&staging2, &sha2).unwrap());
        let _ = std::fs::remove_file(&staging);
        let _ = std::fs::remove_file(&staging2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_fsync_failpoint_fails_closed() {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "agent-bus-artifacts-parent-{}-{n}/artifacts",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
        match ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_PARENT_FSYNC) {
            Err(e) => assert_eq!(e, "artifact dir unavailable: parent fsync"),
            Ok(_) => panic!("parent failpoint must fail closed"),
        }
        assert!(ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_NONE).is_ok());
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn parent_barrier_retried_after_failure_no_existence_skip() {
        // Failed first ancestor sync leaves a visible directory; retry must
        // still attempt all barriers (no exemption from `existed` or
        // `AlreadyExists` visibility). Every successful init establishes
        // full ancestor-chain durability (immediate parent last).
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "agent-bus-artifacts-parent-retry-{}-{n}/artifacts",
            std::process::id()
        ));
        let base = dir.parent().unwrap().to_path_buf();
        let _ = std::fs::remove_dir_all(&base);
        match ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_PARENT_FSYNC) {
            Err(e) => assert_eq!(e, "artifact dir unavailable: parent fsync"),
            Ok(_) => panic!("first parent failpoint must fail closed"),
        }
        assert!(dir.is_dir(), "failed first sync leaves visible dir");
        // Retry with failpoint still fails (would succeed via skip under the
        // old `existed` check); retry with NONE succeeds and is usable.
        match ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_PARENT_FSYNC) {
            Err(e) => assert_eq!(e, "artifact dir unavailable: parent fsync"),
            Ok(_) => panic!("retry parent failpoint must still fail closed"),
        }
        let store = ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_NONE).unwrap();
        let (sha, dedup) = store.put_bytes_durable(b"retry-durable").unwrap();
        assert!(!dedup);
        assert_eq!(store.get_bytes(&sha).unwrap(), b"retry-durable");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ancestor_chain_covers_nested_relative_and_root() {
        // Full ancestor chains, top-down; bare relative syncs CWD, root
        // needs none, nested levels are all attempted (no assumed-durable
        // ancestry). Syntactic only, no IO, no power-loss claim.
        assert_eq!(
            ArtifactStore::ancestor_fsync_chain(Path::new("artifacts")),
            vec![PathBuf::from(".")]
        );
        assert_eq!(
            ArtifactStore::ancestor_fsync_chain(Path::new("sub/artifacts")),
            vec![PathBuf::from("."), PathBuf::from("sub")]
        );
        assert_eq!(
            ArtifactStore::ancestor_fsync_chain(Path::new("a/b/c")),
            vec![
                PathBuf::from("."),
                PathBuf::from("a"),
                PathBuf::from("a/b")
            ]
        );
        assert_eq!(
            ArtifactStore::ancestor_fsync_chain(Path::new("/tmp/x/artifacts")),
            vec![
                PathBuf::from("/"),
                PathBuf::from("/tmp"),
                PathBuf::from("/tmp/x")
            ]
        );
        assert_eq!(
            ArtifactStore::ancestor_fsync_chain(Path::new("/a")),
            vec![PathBuf::from("/")]
        );
        assert!(ArtifactStore::ancestor_fsync_chain(Path::new("/")).is_empty());
        // `"."` as dir self-syncs (best-effort, preserves prior
        // empty-parent behavior; CWD parent outside the path).
        assert_eq!(
            ArtifactStore::ancestor_fsync_chain(Path::new(".")),
            vec![PathBuf::from(".")]
        );
        // `"./artifacts"` yields a single CWD barrier (no duplicate).
        assert_eq!(
            ArtifactStore::ancestor_fsync_chain(Path::new("./artifacts")),
            vec![PathBuf::from(".")]
        );
    }

    #[test]
    fn ancestor_chain_orders_top_down_with_recorder() {
        // Deterministic order proof: recorder observes top-down attempts,
        // positional failures stop at the failed index with prefix synced.
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut base = std::env::temp_dir();
        base.push(format!(
            "agent-bus-artifacts-chain-{}-{n}",
            std::process::id()
        ));
        let dir = base.join("a/b/artifacts");
        std::fs::create_dir_all(&dir).unwrap();
        let chain = ArtifactStore::ancestor_fsync_chain(&dir);
        // Chain is top-down, ends at the immediate parent, and contains
        // every nested level (at least base, base/a, base/a/b for this
        // three-deep creation; earlier system ancestors like `/`, `/tmp`
        // precede them).
        assert!(chain.len() >= 3, "chain={chain:?}");
        assert_eq!(chain[chain.len() - 1], base.join("a/b"));
        assert!(chain.contains(&base.join("a")));
        assert!(chain.contains(&base));
        // Success records the full chain in order.
        let mut record = Vec::new();
        ArtifactStore::fsync_chain_with_recorder(&chain, None, &mut record).unwrap();
        assert_eq!(record, chain);
        // Fail at first: only the first is attempted, none synced after.
        let mut record = Vec::new();
        let err = ArtifactStore::fsync_chain_with_recorder(&chain, Some(0), &mut record).unwrap_err();
        assert_eq!(record, vec![chain[0].clone()]);
        assert!(err.contains("ancestor fsync"), "{err}");
        // Fail in the middle: prefix attempted, suffix untouched.
        let mid = chain.len() / 2;
        let mut record = Vec::new();
        let err = ArtifactStore::fsync_chain_with_recorder(&chain, Some(mid), &mut record)
            .unwrap_err();
        assert_eq!(record, chain[..=mid].to_vec());
        assert!(err.contains("fsync"), "{err}");
        // Fail at last (immediate parent): full prefix synced, then fails
        // with the legacy parent message (compatibility preserved).
        let mut record = Vec::new();
        let err = ArtifactStore::fsync_chain_with_recorder(&chain, Some(chain.len() - 1), &mut record)
            .unwrap_err();
        assert_eq!(record, chain);
        assert_eq!(err, "artifact dir unavailable: parent fsync");
        // Retry after a middle failure re-establishes the full chain
        // (no skip of already-synced prefix, no `AlreadyExists` exemption).
        let mut record = Vec::new();
        ArtifactStore::fsync_chain_with_recorder(&chain, None, &mut record).unwrap();
        assert_eq!(record, chain);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn nested_init_syncs_all_ancestors_with_retry_and_already_exists() {
        // Arbitrary nested `create_dir_all` path: first init establishes
        // all ancestors; retry after a failed barrier re-attempts all;
        // `AlreadyExists` (dir already visible) still syncs all.
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut base = std::env::temp_dir();
        base.push(format!(
            "agent-bus-artifacts-nested-{}-{n}",
            std::process::id()
        ));
        let dir = base.join("lvl1/lvl2/artifacts");
        let _ = std::fs::remove_dir_all(&base);
        // Ancestor failpoint (first) fails before any barrier.
        match ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_ANCESTOR_FSYNC) {
            Err(e) => assert_eq!(e, "artifact dir unavailable: ancestor fsync"),
            Ok(_) => panic!("ancestor failpoint must fail closed"),
        }
        assert!(dir.is_dir(), "failed first sync leaves visible nested dir");
        // Parent failpoint (last) fails after syncing earlier ancestors.
        match ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_PARENT_FSYNC) {
            Err(e) => assert_eq!(e, "artifact dir unavailable: parent fsync"),
            Ok(_) => panic!("parent failpoint must fail closed on nested retry"),
        }
        // Retry with NONE succeeds and is usable (all barriers established).
        let store = ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_NONE).unwrap();
        let (sha, dedup) = store.put_bytes_durable(b"nested-durable").unwrap();
        assert!(!dedup);
        assert_eq!(store.get_bytes(&sha).unwrap(), b"nested-durable");
        drop(store);
        // `AlreadyExists`: dir fully visible, init still syncs all
        // ancestors (failpoints still fail, proving no existence skip).
        match ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_ANCESTOR_FSYNC) {
            Err(e) => assert_eq!(e, "artifact dir unavailable: ancestor fsync"),
            Ok(_) => panic!("ancestor failpoint must fail on AlreadyExists"),
        }
        match ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_PARENT_FSYNC) {
            Err(e) => assert_eq!(e, "artifact dir unavailable: parent fsync"),
            Ok(_) => panic!("parent failpoint must fail on AlreadyExists"),
        }
        assert!(ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_NONE).is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn unlink_owned_treats_not_found_as_success_counts_other_errors() {
        let (store, dir) = temp_store("unlink-owned");
        assert_eq!(store.staging_cleanup_failed(), 0);
        // `NotFound` (already gone) succeeds without counting.
        let missing = dir.join(".up-ffffffffffffffff");
        assert!(store.unlink_staging_owned(&missing).is_ok());
        assert_eq!(store.staging_cleanup_failed(), 0);
        // Real file unlinks successfully without counting.
        let staged = dir.join(".up-0123456789abcd");
        std::fs::write(&staged, b"x").unwrap();
        assert!(store.unlink_staging_owned(&staged).is_ok());
        assert!(!staged.exists());
        assert_eq!(store.staging_cleanup_failed(), 0);
        // Directory at staging path fails (even as root, `remove_file`
        // on a dir errors), counts once, staging preserved for retry.
        let dir_path = dir.join(".up-0123456789abce");
        std::fs::create_dir_all(&dir_path).unwrap();
        let err = store.unlink_staging_owned(&dir_path).unwrap_err();
        assert!(err.starts_with("staging cleanup failed:"), "{err}");
        assert_eq!(store.staging_cleanup_failed(), 1);
        assert!(dir_path.is_dir(), "failed unlink preserves staging for retry");
        // Injected failpoint fails without touching the filesystem,
        // counts, then auto-clears for the retry.
        let staged2 = dir.join(".up-0123456789abcf");
        std::fs::write(&staged2, b"y").unwrap();
        store.set_unlink_failpoint_for_test(1);
        let err = store.unlink_staging_owned(&staged2).unwrap_err();
        assert_eq!(err, "staging cleanup failed: injected unlink failure");
        assert_eq!(store.staging_cleanup_failed(), 2);
        assert!(staged2.exists(), "injected failure preserves staging");
        assert!(store.unlink_staging_owned(&staged2).is_ok());
        assert!(!staged2.exists());
        assert_eq!(store.staging_cleanup_failed(), 2);
        let _ = std::fs::remove_dir_all(&dir_path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_bytes_bounded_single_handle() {
        let (store, dir) = temp_store("bounded-read");
        // Empty object roundtrips (size 0 allowed via put).
        let (sha_empty, _) = store.put_bytes_durable(b"").unwrap();
        assert_eq!(store.get_bytes(&sha_empty).unwrap(), b"");
        assert_eq!(store.stat(&sha_empty).unwrap(), 0);
        // Valid small object: get/stat/range agree.
        let raw = b"bounded";
        let (sha, _) = store.put_bytes_durable(raw).unwrap();
        assert_eq!(store.get_bytes(&sha).unwrap(), raw);
        assert_eq!(store.stat(&sha).unwrap(), raw.len() as u64);
        let (chunk, size) = store.range(&sha, 0, 100).unwrap();
        assert_eq!(chunk, raw);
        assert_eq!(size, raw.len() as u64);
        // Tampered oversize (sparse ART_MAX+1, no 33 MiB write):
        // get refuses as not-found (never OOM), stat/range report size
        // truthfully with bounded reads (consistent, no unbounded alloc).
        let sha_big = sha256_hex(b"big");
        let big_path = store.object_path(&sha_big).unwrap();
        {
            let f = std::fs::File::create(&big_path).unwrap();
            f.set_len(ART_MAX + 1).unwrap();
        }
        assert_eq!(
            store.get_bytes(&sha_big),
            Err("artifact not found".to_string())
        );
        assert_eq!(store.stat(&sha_big).unwrap(), ART_MAX + 1);
        let (capped, reported) = store.range(&sha_big, 0, CHUNK_MAX).unwrap();
        assert_eq!(reported, ART_MAX + 1);
        assert_eq!(capped.len() as u64, CHUNK_MAX);
        // Exactly ART_MAX reads (bounded 32 MiB allocation, sparse zeros).
        let sha_max = sha256_hex(b"max");
        let max_path = store.object_path(&sha_max).unwrap();
        {
            let f = std::fs::File::create(&max_path).unwrap();
            f.set_len(ART_MAX).unwrap();
        }
        assert_eq!(store.get_bytes(&sha_max).unwrap().len() as u64, ART_MAX);
        assert_eq!(store.stat(&sha_max).unwrap(), ART_MAX);
        // Directories and missing miss consistently across get/stat/range.
        let sha_dir = sha256_hex(b"isdir");
        let dir_path = store.object_path(&sha_dir).unwrap();
        std::fs::create_dir_all(&dir_path).unwrap();
        assert_eq!(
            store.get_bytes(&sha_dir),
            Err("artifact not found".to_string())
        );
        assert_eq!(store.stat(&sha_dir), Err("artifact not found".to_string()));
        assert_eq!(
            store.range(&sha_dir, 0, 1),
            Err("artifact not found".to_string())
        );
        let _ = std::fs::remove_dir_all(&dir_path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_limits_defaults_are_finite_and_documented() {
        // Pins the documented production defaults (any change must
        // update `docs/NATIVE_ARTIFACTS.md` + rustdoc together).
        let d = StagingLimits::default();
        assert_eq!(d.max_uploads_global, 1024);
        assert_eq!(d.max_uploads_per_owner, 128);
        assert_eq!(d.max_declared_bytes_global, 4 * 1024 * 1024 * 1024);
        assert_eq!(d.max_declared_bytes_per_owner, 512 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_UPLOADS_GLOBAL, 1024);
        assert_eq!(DEFAULT_MAX_UPLOADS_PER_OWNER, 128);
        assert_eq!(DEFAULT_MAX_STAGING_BYTES_GLOBAL, 4 * 1024 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_STAGING_BYTES_PER_OWNER, 512 * 1024 * 1024);
        assert_eq!(STAGING_COUNT_ERROR, "too many pending uploads");
        assert_eq!(STAGING_BYTES_ERROR, "pending upload bytes exceeded");
        let (store, dir) = temp_store("staging-defaults");
        assert_eq!(store.staging_limits(), StagingLimits::default());
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_admission_enforces_all_four_bounds() {
        // Tiny limits hit each bound deterministically: per-owner
        // count, global bytes, global count, per-owner bytes.
        let limits = StagingLimits::for_test(3, 2, 100, 70);
        let (store, dir) = temp_store_with_limits("staging-bounds", limits);
        assert_eq!(store.staging_limits(), limits);
        let a1 = store.init_upload("alice", 30, None).unwrap();
        assert_eq!(store.staging_reserved_for_test(), (1, 30));
        let a2 = store.init_upload("alice", 30, None).unwrap();
        assert_eq!(store.staging_reserved_for_test(), (2, 60));
        // Per-owner count (alice 2/2): denied, takes nothing.
        assert_eq!(
            store.init_upload("alice", 10, None),
            Err(STAGING_COUNT_ERROR.to_string())
        );
        assert_eq!(store.staging_reserved_for_test(), (2, 60));
        // Global bytes (60 + 50 > 100): denied, takes nothing.
        assert_eq!(
            store.init_upload("bob", 50, None),
            Err(STAGING_BYTES_ERROR.to_string())
        );
        assert_eq!(store.staging_reserved_for_test(), (2, 60));
        let b1 = store.init_upload("bob", 30, None).unwrap();
        assert_eq!(store.staging_reserved_for_test(), (3, 90));
        // Global count (3/3): denied, takes nothing.
        assert_eq!(
            store.init_upload("bob", 1, None),
            Err(STAGING_COUNT_ERROR.to_string())
        );
        assert_eq!(store.staging_reserved_for_test(), (3, 90));
        // Release alice's two: counters drop, her per-owner entry is
        // removed (accounting itself stays bounded).
        assert!(store.pop_upload(&a1).is_some());
        assert!(store.pop_upload(&a2).is_some());
        assert_eq!(store.staging_reserved_for_test(), (1, 30));
        assert!(!store.uploads.lock().unwrap().per_owner.contains_key("alice"));
        // Per-owner bytes (bob 30 + 50 = 80 > 70, global 30 + 50 = 80
        // fits): denied with the bytes string.
        assert_eq!(
            store.init_upload("bob", 50, None),
            Err(STAGING_BYTES_ERROR.to_string())
        );
        assert_eq!(store.staging_reserved_for_test(), (1, 30));
        // Boundary equality admits (70/70 owner, 70/100 global).
        let b2 = store.init_upload("bob", 40, None).unwrap();
        assert_eq!(store.staging_reserved_for_test(), (2, 70));
        // Staging admission never charges committed usage and never
        // bumps the quota-denial counter (orthogonal accounting).
        assert_eq!(store.usage_of("alice"), 0);
        assert_eq!(store.usage_of("bob"), 0);
        assert_eq!(store.quota_denied(), 0);
        // Release everything: zero counters, empty owner map, fresh
        // admissions work again (no leaked reservation).
        assert!(store.pop_upload(&b1).is_some());
        assert!(store.pop_upload(&b2).is_some());
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        assert!(store.uploads.lock().unwrap().per_owner.is_empty());
        let c1 = store.init_upload("carol", 70, None).unwrap();
        assert_eq!(store.staging_reserved_for_test(), (1, 70));
        assert!(store.pop_upload(&c1).is_some());
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_init_serializes_creation_without_holding_global_lock() {
        let (store, dir) = temp_store("init-serialization");
        let mut phases = Vec::new();
        let uid = store
            .init_upload_observed("alice", 10, None, |uid, path, phase| {
                let handle = store.lookup_upload(uid).expect("published owner");
                assert!(matches!(
                    handle.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                assert!(store.uploads.try_lock().is_ok());
                assert_eq!(store.staging_reserved_for_test(), (1, 10));
                assert_eq!(path.exists(), phase == UploadInitPhase::AfterCreate);
                phases.push(phase);
            })
            .unwrap();
        assert_eq!(
            phases,
            [UploadInitPhase::BeforeCreate, UploadInitPhase::AfterCreate]
        );
        let handle = store.lookup_upload(&uid).unwrap();
        {
            let mut up = handle.lock().unwrap();
            assert_eq!(up.state, UploadState::Active);
            assert_eq!(up.agent, "alice");
            assert_eq!(up.size, 10);
            store.unlink_staging_owned(&up.path).unwrap();
            up.state = UploadState::Aborted;
        }
        assert!(store.pop_upload(&uid).is_some());
        assert!(store.pop_upload(&uid).is_none());
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        assert_eq!(store.usage_of("alice"), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn staging_init_collision_preserves_existing_file_and_releases_once() {
        let limits = StagingLimits::for_test(1, 1, 10, 10);
        let (store, dir) = temp_store_with_limits("init-collision", limits);
        let mut collided: Option<(String, PathBuf, Arc<Mutex<PendingUpload>>)> = None;
        let uid = store
            .init_upload_observed("alice", 10, None, |uid, path, phase| {
                if phase != UploadInitPhase::BeforeCreate {
                    return;
                }
                assert_eq!(store.staging_reserved_for_test(), (1, 10));
                if let Some((old_uid, old_path, old_handle)) = &collided {
                    assert!(store.lookup_upload(old_uid).is_none());
                    let old: &Arc<Mutex<PendingUpload>> = old_handle;
                    assert_eq!(old.lock().unwrap().state, UploadState::Aborted);
                    assert_eq!(std::fs::read(old_path).unwrap(), b"existing");
                } else {
                    std::fs::write(path, b"existing").unwrap();
                    collided = Some((
                        uid.to_string(),
                        path.to_path_buf(),
                        store.lookup_upload(uid).unwrap(),
                    ));
                }
            })
            .unwrap();
        let (old_uid, old_path, old_handle) = collided.unwrap();
        assert_ne!(old_uid, uid);
        assert_eq!(old_handle.lock().unwrap().state, UploadState::Aborted);
        assert!(store.pop_upload(&old_uid).is_none());
        assert_eq!(store.staging_reserved_for_test(), (1, 10));
        assert_eq!(std::fs::read(old_path).unwrap(), b"existing");
        assert!(dir.join(format!(".up-{uid}")).is_file());
        assert_eq!(store.staging_cleanup_failed(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn staging_init_collision_exhaustion_keeps_no_reservation() {
        let limits = StagingLimits::for_test(1, 1, 10, 10);
        let (store, dir) = temp_store_with_limits("init-collision-exhausted", limits);
        let mut attempts = Vec::new();
        let result = store.init_upload_observed("alice", 10, None, |uid, path, phase| {
            assert_eq!(phase, UploadInitPhase::BeforeCreate);
            assert_eq!(store.staging_reserved_for_test(), (1, 10));
            std::fs::write(path, b"existing").unwrap();
            attempts.push((path.to_path_buf(), store.lookup_upload(uid).unwrap()));
        });
        assert_eq!(result, Err("stage failed: id collision".to_string()));
        assert_eq!(attempts.len(), 8);
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        assert!(store.uploads.lock().unwrap().per_owner.is_empty());
        for (path, handle) in attempts {
            assert_eq!(handle.lock().unwrap().state, UploadState::Aborted);
            assert_eq!(std::fs::read(path).unwrap(), b"existing");
        }
        assert_eq!(store.staging_cleanup_failed(), 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn staging_init_create_error_is_terminal_before_reservation_release() {
        let (store, dir) = temp_store("init-terminal-error");
        let mut observed = None;
        let result = store.init_upload_observed("alice", 10, None, |uid, _, phase| {
            assert_eq!(phase, UploadInitPhase::BeforeCreate);
            observed = store.lookup_upload(uid);
            assert_eq!(store.staging_reserved_for_test(), (1, 10));
            // Ordinary local creation failure, independent of UID or mode.
            std::fs::remove_dir(&dir).unwrap();
            std::fs::write(&dir, b"not a directory").unwrap();
        });
        assert!(result.unwrap_err().starts_with("stage failed:"));
        assert_eq!(observed.unwrap().lock().unwrap().state, UploadState::Aborted);
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        assert!(store.uploads.lock().unwrap().map.is_empty());
        assert_eq!(store.staging_cleanup_failed(), 0);
        assert_eq!(store.usage_of("alice"), 0);
        std::fs::remove_file(&dir).unwrap();
        std::fs::create_dir(&dir).unwrap();
        assert!(store.init_upload("alice", 10, None).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn staging_init_io_failure_rolls_back_reservation() {
        // Deterministic even as root: the store dir replaced by a
        // regular file makes staging creation fail with ENOTDIR (no
        // permission trick). The failed init must leave no reservation
        // and no map entry; restoring the dir admits cleanly.
        let limits = StagingLimits::for_test(1, 8, 1 << 40, 1 << 40);
        let (store, dir) = temp_store_with_limits("staging-rollback", limits);
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::File::create(&dir).unwrap();
        let err = store.init_upload("alice", 10, None).unwrap_err();
        assert!(err.starts_with("stage failed:"), "{err}");
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        assert!(store.uploads.lock().unwrap().map.is_empty());
        assert!(store.uploads.lock().unwrap().per_owner.is_empty());
        // Restore the dir: the rolled-back slot admits (limit 1 proves
        // no leaked reservation), staging file exists, pop releases.
        std::fs::remove_file(&dir).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let uid = store.init_upload("alice", 10, None).unwrap();
        assert_eq!(store.staging_reserved_for_test(), (1, 10));
        assert!(dir.join(format!(".up-{uid}")).is_file());
        assert!(store.pop_upload(&uid).is_some());
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_concurrent_admission_is_bounded() {
        // 16 threads race one store with a global limit of 5: exactly 5
        // admit, 11 deny with the count string, counters are exact, and
        // every reservation releases (no lost or double release).
        let limits = StagingLimits::for_test(5, 64, 1 << 40, 1 << 40);
        let (store, dir) = temp_store_with_limits("staging-race", limits);
        let barrier = std::sync::Barrier::new(16);
        let (ok_tx, ok_rx) = std::sync::mpsc::channel();
        let (err_tx, err_rx) = std::sync::mpsc::channel();
        std::thread::scope(|s| {
            for _ in 0..16 {
                s.spawn(|| {
                    barrier.wait();
                    match store.init_upload("racer", 10, None) {
                        Ok(uid) => ok_tx.send(uid).unwrap(),
                        Err(e) => err_tx.send(e).unwrap(),
                    }
                });
            }
        });
        drop(ok_tx);
        drop(err_tx);
        let oks: Vec<String> = ok_rx.iter().collect();
        let errs: Vec<String> = err_rx.iter().collect();
        assert_eq!(oks.len(), 5, "exactly the limit admits: {oks:?} {errs:?}");
        assert_eq!(errs.len(), 11);
        for e in &errs {
            assert_eq!(e, STAGING_COUNT_ERROR, "{e}");
        }
        assert_eq!(store.staging_reserved_for_test(), (5, 50));
        for uid in &oks {
            assert!(store.pop_upload(uid).is_some());
        }
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        assert!(store.uploads.lock().unwrap().per_owner.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_retained_pending_holds_until_pop_without_uncharge() {
        // A retained `CommittedCleanupPending` orphan (wire sets this on
        // commit-unlink failure) keeps holding its reservation until the
        // confirming pop; releasing never uncharges committed usage, and
        // a double pop releases nothing.
        let (store, dir) = temp_store("staging-retain");
        assert!(store.try_charge("alice", 18, Quota::Unlimited).is_ok());
        let uid = store.init_upload("alice", 18, None).unwrap();
        assert_eq!(store.staging_reserved_for_test(), (1, 18));
        {
            let handle = store.lookup_upload(&uid).unwrap();
            handle.lock().unwrap().state = UploadState::CommittedCleanupPending;
        }
        assert_eq!(store.staging_reserved_for_test(), (1, 18));
        assert!(store.pop_upload(&uid).is_some());
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        assert!(store.pop_upload(&uid).is_none());
        assert_eq!(store.staging_reserved_for_test(), (0, 0));
        // Committed usage is separate: the staging release kept it.
        assert_eq!(store.usage_of("alice"), 18);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ancestor_recorder_matches_production_failpoints() {
        // The recorder runs the actual production loop
        // (`run_ancestor_chain`, not a copy): production semantic
        // failpoints and recorder positional failpoints agree on every
        // failure string and on success for the same nested chain.
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut base = std::env::temp_dir();
        base.push(format!(
            "agent-bus-artifacts-loop-agree-{}-{n}",
            std::process::id()
        ));
        let dir = base.join("lvl1/lvl2/artifacts");
        let _ = std::fs::remove_dir_all(&base);
        let chain = ArtifactStore::ancestor_fsync_chain(&dir);
        assert!(chain.len() >= 3, "chain={chain:?}");
        let last = chain.len() - 1;
        // Real syncs need the chain to exist: production creates it, so
        // create it once up front (the recorder only syncs, never mkdirs).
        std::fs::create_dir_all(&dir).unwrap();
        // Success agrees (recorder observes the full production order).
        let mut record = Vec::new();
        ArtifactStore::fsync_chain_with_recorder(&chain, None, &mut record).unwrap();
        assert_eq!(record, chain);
        assert!(ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_NONE).is_ok());
        // Parent/last failpoint agrees (prefix synced, parent message).
        let mut record = Vec::new();
        let rec_err =
            ArtifactStore::fsync_chain_with_recorder(&chain, Some(last), &mut record).unwrap_err();
        let prod_err = match ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_PARENT_FSYNC) {
            Err(e) => e,
            Ok(_) => panic!("parent failpoint must fail closed"),
        };
        assert_eq!(rec_err, prod_err);
        assert_eq!(rec_err, "artifact dir unavailable: parent fsync");
        assert_eq!(record, chain);
        // Ancestor/first failpoint agrees (nothing synced, ancestor msg).
        let mut record = Vec::new();
        let rec_err =
            ArtifactStore::fsync_chain_with_recorder(&chain, Some(0), &mut record).unwrap_err();
        let prod_err = match ArtifactStore::new_with_failpoint(dir.clone(), ART_FAIL_ANCESTOR_FSYNC) {
            Err(e) => e,
            Ok(_) => panic!("ancestor failpoint must fail closed"),
        };
        assert_eq!(rec_err, prod_err);
        assert_eq!(rec_err, "artifact dir unavailable: ancestor fsync");
        assert_eq!(record, vec![chain[0].clone()]);
        let _ = std::fs::remove_dir_all(&base);
    }
}

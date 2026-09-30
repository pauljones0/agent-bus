//! JSON-lines TCP wire: authenticated hello/post/fetch/claim/kv/presence/introspection/subscription ops.
//!
//! Frame format mirrors the transitional broker: one JSON object per line,
//! requests carry `op` + `req_id`, responses echo `req_id` with `ok` or
//! `error`. Owner identity always comes from the authenticated hello agent,
//! never from payload fields. Claim grants and KV mutations fsync before ack
//! (broker-side durability, not a client flag). Presence (`heartbeat`/
//! `agents` via `crate::presence`) is memory-only, never WAL: hello
//! assigns `"online"` only to absent agents (reconnects preserve),
//! every authenticated op refreshes liveness (`ping` never does),
//! `agents` exposes only `{status, age_s, online}` with `online <= 600s`
//! and lazy `>86400s` pruning plus the idle maintenance worker (see
//! `docs/NATIVE_EXPIRY_MAINTENANCE.md`), and presence never renews leases.
//!
//! Authorization is the reviewed `crate::acl` policy (no duplicate parser
//! or matcher here): `hello` uses `TokenStore::authenticate` (unknown/
//! empty as `"auth failed"`, passed `exp` as `"token expired"` with
//! `now == exp` still live, name mismatch as `"agent/token mismatch"`),
//! `post` uses `Policy::can_publish` (Unicode scalar fnmatch, empty denied,
//! wildcard topics allowed when a grant matches, matching legacy),
//! `fetch` uses `Policy::can_fetch` (empty and `*?[` topics denied, else
//! prefix-cover over `subscribe`), and KV ops use the effective per-key
//! grants (`can_kv_read`/`can_kv_write` with missing/null fallback to
//! `subscribe`/`publish`, explicit `[]` denying without fallback) plus
//! `can_kv_list` prefix cover for listings, with per-key filtering before
//! the 1000 cap. There is no admin publish/subscribe bypass (matching
//! legacy, where `agent: "*"` bypasses only rate limits): scoped and admin
//! tokens alike need explicit grants. Malformed `tokens.json` (bad root,
//! bad grant type, bad glob) fails closed at load with an index-based
//! diagnostic that never echoes the token. KV mutations follow the reviewed
//! `crate::kv` validate-before-durability discipline: `prepare_*` renders
//! the canonical record, the WAL append+fsync runs first, and memory
//! mutates only on success, so a failed append leaves old state untouched.
//! Fractional `ttl_ms` is preserved exactly (`now + ttl/1000`, no
//! rounding), matching legacy float division; `0`/`0.0`/`-0.0`/null/
//! missing mean no expiry. Appends use the robust rollback discipline:
//! the pre-append length is recorded fail-closed (only a missing file may
//! mean zero; any other metadata error fails before the append instead of
//! authorizing a truncate-to-zero rollback), and any `opened=true` failure
//! truncates back (preventing torn-tail concatenation and replay
//! resurrection of the failed record); a failed rollback poisons the
//! WAL (mutations refuse with `wal poisoned`, reads stay available).
//! Deterministic test hooks (`set_fixed_now`, `set_append_failpoint`)
//! are `Arc`-shared with the serving thread; production leaves them at
//! system time / `NONE`. Legacy `kv.json` snapshots are explicitly
//! unsupported: startup refuses when the sibling snapshot exists (see
//! `crate::wal::snapshot_path_for`).
//! Preserved bounds: the 256 MiB connection frame cap, the 1000-message /
//! 4 MiB history page bounds, strict numeric request validation, and the
//! `wire::Client` RPC deadlines (5s connect per address, 10s per RPC,
//! 8 MiB reply cap, single attempt, no token echo). Introspection
//! (`topics`/`limits`/`stats` via `crate::presence::round1_py` and policy
//! visibility) is source-backed; see `docs/NATIVE_INTROSPECTION.md`.
//! Post retry idempotency (`msg_id`, see `docs/NATIVE_IDEMPOTENCY.md`):
//! explicit non-empty `msg_id` dedups within retained live history
//! (`RETAIN_PER_TOPIC`, newest live match wins); same sender/topic/id +
//! equal payload/corr/reply returns the original `{id, seq}` with
//! `dup: true` without new seq/WAL/`posts`; different sender or payload
//! refuses as `msg_id conflict` without mutation; expired/evicted ids are
//! outside the window (retry becomes a new post, never a fabricated
//! receipt); ACL runs before any disclosure; failed appends leave no
//! trace (safe retry); lookup+reserve+commit hold one lock so concurrent
//! duplicates serialize. Auto ids (missing/empty/non-string) always post
//! new. Subscriptions (`subscribe`/`unsubscribe`/`subs` via
//! `crate::subs`: exact/glob patterns, conservative grant cover,
//! per-connection ownership, `from_seq`/`tail` replay with expiry and
//! exact-topic cursors, live fan-out after WAL success with no dup on
//! retained retry, atomic registration/replay/live, bounded queues
//! with explicit drop/replay accounting; see
//! `docs/NATIVE_SUBSCRIPTIONS.md`) and delivery counters
//! (`deliveries`/`drops`/`replays`/`subs` in `stats`) are live.
//! Post rate enforcement (`rate_per_s`/`topic_rates` via `crate::rate`:
//! ordered first-match, per-agent/rule buckets, `rate_limited` in
//! `stats`; see `docs/NATIVE_RATE_LIMITS.md`) is live. Token admin
//! (`token_issue`/`token_revoke`/`token_claim` via `crate::tokens`: admin
//! vs claim-only auth, bounded names, fixed claim grants, rolling 3/hour,
//! presence retirement post-commit, `tmp(0600)+fsync+rename+dir-fsync`
//! with rollback/poison, prompt revocation revalidation; see
//! `docs/NATIVE_TOKEN_ADMIN.md`) is live. Artifact bytes/quotas
//! (`art_put`/`art_get`/`art_init`/`art_chunk`/`art_commit`/
//! `art_abort`/`art_range`/`art_stat` via `crate::artifacts`:
//! content-addressed sha256, private staging, atomic publish,
//! reservation quota with WAL-before-ack, `art_used_bytes` live,
//! `quota_denied` live; see `docs/NATIVE_ARTIFACTS.md`) are live.
//! `Policy::enforce_artifact_quota` stays `Unsupported` for ACL-only
//! callers (enforcement lives in wire, like `enforce_rate_limit`).

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
    Arc, Mutex,
};

use serde_json::{json, Value};

use crate::acl::{Policy, TokenStore};
use crate::artifacts::ArtifactStore;
use crate::claims::{ClaimError, ClaimWal, WalClaim};
use crate::history::{history_page, Msg};
use crate::kv::KvError;
use crate::presence::{coerce_status, round1_py, PresenceStore};
use crate::rate::RateLimiter;
use crate::subs::{
    ConnOutbox, Matcher, OutFrame, PendingState, SubState, SubsRegistry, Subscription,
    SUBS_QUEUE_MAX, SUBS_REPLAY_CAP,
};
use crate::wal::{
    acquire_wal_lock, append_fsync_detailed, append_line_fsync_detailed, replay, snapshot_path_for,
    truncate_to, BusState, ReplayError, WalLock, APPEND_FAIL_NONE,
};

/// Maximum inbound frame bytes per connection (mirrors the Python broker).
pub const FRAME_LIMIT: usize = 256 * 1024 * 1024;

/// Default idle maintenance interval for production `serve` (legacy
/// `periodic_loop` 5s parity; see `docs/NATIVE_EXPIRY_MAINTENANCE.md`).
/// Tests use explicit ticks or short intervals, never multi-minute sleeps.
pub const MAINTENANCE_INTERVAL_DEFAULT: std::time::Duration = std::time::Duration::from_secs(5);

/// Owned accept-loop poll slice: the accept thread sleeps this long when no
/// peer is waiting (and after a failed accept), so a stop is noticed within
/// one slice without busy spinning. 20ms also bounds worst-case admit
/// latency for a newly arrived peer.
const ACCEPT_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// One maintenance-tick outcome: expired payloads released per store.
///
/// Counts are removed entries only (never live), for deterministic tests and
/// operator logs. Empty topics are kept (high-water `seq` preserved); only
/// `msgs` payloads are dropped. No WAL/filesystem IO is performed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    /// Topics scanned this tick.
    pub topics_scanned: usize,
    /// Expired topic payloads dropped (`now > exp`, high-water kept).
    pub msgs_removed: usize,
    /// Expired KV keys dropped (`now > exp`).
    pub kv_removed: usize,
    /// Expired leases dropped (`now >= expires_at`; receipts kept).
    pub leases_removed: usize,
    /// Stale presence entries dropped (`now - last_seen > 86400`).
    pub presence_removed: usize,
    /// Expired retired suppressions dropped (`now - ts > 3600`).
    pub retired_removed: usize,
}

impl MaintenanceReport {
    /// Total entries released across all stores.
    pub fn total_removed(&self) -> usize {
        self.msgs_removed
            + self.kv_removed
            + self.leases_removed
            + self.presence_removed
            + self.retired_removed
    }

    /// True when nothing was released (idle or all fresh).
    pub fn is_empty(&self) -> bool {
        self.total_removed() == 0
    }
}

/// Lifecycle-owned idle expiry worker: a single bounded thread that ticks
/// [`Server::maintenance_tick`] every `interval`.
///
/// Created by [`Server::spawn_maintenance_worker`]; dropping the guard
/// signals stop and joins the thread (clean shutdown, no detached/endless
/// worker, no per-entry/per-topic threads). The thread waits first, then
/// ticks, matching legacy `periodic_loop` (`sleep(5)` before the first
/// purge). Stop wakes that wait; a tick already in progress must finish
/// before the guard can join it.
/// Ticks hold each state lock briefly, perform no WAL/filesystem IO, and
/// use the server clock (`fixed_now` when pinned, else system time).
pub struct MaintenanceWorker {
    stop: Arc<AtomicBool>,
    wake: std::sync::mpsc::SyncSender<()>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for MaintenanceWorker {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

impl MaintenanceWorker {
    /// Signal stop and wait for the thread (idempotent; `Drop` does the same).
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            // At most one message is sent. It also covers shutdown before
            // the worker reaches its first wait, without a lost wakeup.
            let _ = self.wake.send(());
            let _ = h.join();
        }
    }

    /// True after `shutdown`/drop started (thread may still be joining).
    pub fn is_stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// Transport-agnostic byte stream: TCP everywhere, Unix-domain on `cfg(unix)`.
///
/// Both variants preserve the same contract the TCP-only code relied on:
/// `Read`/`Write`, `try_clone` (reader/writer split plus shutdown clones),
/// `shutdown` (EOF unblock at owned shutdown), `set_read_timeout`/
/// `set_write_timeout` (client RPC deadlines), and an internal-only
/// `peer_label` (never wire-visible, never panics, never echoes secrets).
/// Framing, auth, ACL, history, durability and state logic stay shared;
/// only the socket type differs. TLS remains separate migration debt.
pub enum WireStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl std::io::Read for WireStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WireStream::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            WireStream::Unix(s) => s.read(buf),
        }
    }
}

impl std::io::Write for WireStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WireStream::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            WireStream::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WireStream::Tcp(s) => s.flush(),
            #[cfg(unix)]
            WireStream::Unix(s) => s.flush(),
        }
    }
}

impl WireStream {
    pub fn try_clone(&self) -> std::io::Result<WireStream> {
        match self {
            WireStream::Tcp(s) => Ok(WireStream::Tcp(s.try_clone()?)),
            #[cfg(unix)]
            WireStream::Unix(s) => Ok(WireStream::Unix(s.try_clone()?)),
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        match self {
            WireStream::Tcp(s) => s.shutdown(how),
            #[cfg(unix)]
            WireStream::Unix(s) => s.shutdown(how),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        match self {
            WireStream::Tcp(s) => s.set_read_timeout(timeout),
            #[cfg(unix)]
            WireStream::Unix(s) => s.set_read_timeout(timeout),
        }
    }

    pub fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        match self {
            WireStream::Tcp(s) => s.set_write_timeout(timeout),
            #[cfg(unix)]
            WireStream::Unix(s) => s.set_write_timeout(timeout),
        }
    }

    /// Internal-only peer label (never wire-visible). TCP keeps the
    /// `SocketAddr` text (or `"unknown"`); Unix uses `"unix:<path>"` when
    /// the peer address carries a pathname, else `"unix"`. Never panics.
    pub fn peer_label(&self) -> String {
        match self {
            WireStream::Tcp(s) => s
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            #[cfg(unix)]
            WireStream::Unix(s) => match s.peer_addr() {
                Ok(addr) => match addr.as_pathname() {
                    Some(p) => format!("unix:{}", p.display()),
                    None => "unix".to_string(),
                },
                Err(_) => "unix".to_string(),
            },
        }
    }
}

/// Owned Unix socket path evidence (only on `cfg(unix)`): the pathname this
/// `OwnedBroker` created, plus the device/inode observed immediately after
/// `bind`. Cleanup removes the path only when it still refers to the same
/// socket inode; a replaced path is left alone, never blindly unlinked.
#[cfg(unix)]
struct UnixSocketOwnership {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

/// Owned-broker connection registry: one `(handler, shutdown-socket)` pair
/// per admitted connection. The accept thread(s) push (reaping finished
/// pairs past 64 entries); shutdown drains and joins every handler.
type ConnRegistry = Arc<Mutex<Vec<(std::thread::JoinHandle<()>, WireStream)>>>;

/// Owned broker accept-loop lifecycle: one accept thread per configured
/// listener (one for TCP-only or Unix-only, two for simultaneous
/// TCP+Unix), all admitted connection threads, and the idle maintenance
/// worker, with explicit stop/join and a `Drop` fallback.
///
/// Created by [`Server::serve_owned`] (TCP-only), `serve_owned_unix`
/// (Unix-only, `cfg(unix)`), or `serve_owned_dual` (simultaneous TCP+Unix,
/// `cfg(unix)`); the native `serve` CLI uses TCP-only or dual.
/// [`Server::serve`] keeps the legacy detached TCP behavior for existing
/// tests. Exactly one `OwnedBroker` may be live per `Server` at a time: a
/// second owned serve while one is live fails instead of starting a
/// duplicate accept loop or maintenance worker. Sequential start/stop/
/// start is allowed once the previous owner fully joined.
///
/// All configured listeners belong to this one owner, never to one guard
/// per listener: stop admits across every listener, every accept thread
/// is joined, then every connection/writer, then maintenance. A Unix
/// socket is removed only when this owner created it and the pathname
/// still refers to the same socket inode; a pre-existing or replaced
/// path is never unlinked.
///
/// Shutdown contract (see `docs/NATIVE_BROKER_LIFECYCLE.md`):
/// - Stop admitting first: each accept thread drops its listener (racing
///   accepts after the stop flag are dropped, never served) and exits
///   within one [`ACCEPT_POLL`] slice.
/// - Every admitted connection reader is then unblocked by shutting down
///   its registered socket, so each handler runs its normal disconnect
///   cleanup (owned subscriptions removed, owned pending uploads aborted,
///   outbox closed, writer joined) and is joined: no detached connection
///   or writer thread survives shutdown.
/// - An already-admitted op runs to completion (fsync or error) under its
///   brief state lock; its reply is queued, then discarded with the outbox
///   at disconnect cleanup (EOF path): shutdown never drains queued
///   replies behind a slow peer. Completion of an in-progress operation
///   or filesystem call has no wall-clock bound; this is not a shutdown
///   deadline guarantee.
/// - Durability: a reply is built only after its WAL append+fsync (or
///   after a read-only op), so any acknowledgement the client received is
///   already durable and replays after restart. An op without an
///   acknowledgement has unknown outcome: the client reconnects and
///   retries (explicit `msg_id` posts dedup within the retained window).
/// - The maintenance worker stops (an in-progress tick finishes first)
///   and is joined last. No final WAL flush or KV snapshot is needed:
///   every record is fsync'd at append and replay is WAL-only.
/// - Unix cleanup (when owned): the socket this owner created is unlinked
///   after the joins, only after re-verifying device/inode still match.
///   A missing path is already clean; a replaced path is left alone.
/// - Thread-creation limits (source-reviewed, not failure-tested):
///   `std::thread::spawn` panics rather than returning a startup error,
///   so exhaustion is not a fallible `serve_owned` path. Join results
///   are intentionally ignored (`let _ = h.join()`): shutdown completes
///   even if a handler panicked, but a panic always indicates a bug and
///   ordinary successful runs never panic.
pub struct OwnedBroker {
    // Consume this ownership token exactly once. An old, already-joined
    // handle must not release a later owner's serving guard on drop.
    serving: Option<Arc<AtomicBool>>,
    stop: Arc<AtomicBool>,
    accept: Vec<std::thread::JoinHandle<()>>,
    conns: ConnRegistry,
    maintenance: Option<MaintenanceWorker>,
    #[cfg(unix)]
    unix_ownership: Option<UnixSocketOwnership>,
}

impl Drop for OwnedBroker {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

impl OwnedBroker {
    /// Signal stop (idempotent): each accept loop exits within one poll
    /// slice and drops its listener. Connection/maintenance joins happen
    /// in [`OwnedBroker::stop_and_join`]/`shutdown`/drop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    /// True after [`OwnedBroker::stop`] started (threads may still join).
    pub fn is_stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Currently live (unfinished) connection handlers (test introspection).
    pub fn live_connections(&self) -> usize {
        self.conns
            .lock()
            .unwrap()
            .iter()
            .filter(|(h, _)| !h.is_finished())
            .count()
    }

    /// Stop and join everything: every accept thread (each listener
    /// closed, live sockets shut down), then every admitted connection
    /// handler (normal disconnect cleanup each), then the maintenance
    /// worker, then the owned Unix socket unlink (when this owner
    /// created one and it still matches). Idempotent; `Drop` does the
    /// same. Releases the per-`Server` serving guard so a later owned
    /// serve may start.
    pub fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for h in self.accept.drain(..) {
            let _ = h.join();
        }
        // Each accept thread already shut every registered socket down,
        // so each reader sees EOF and runs disconnect cleanup; join all.
        // No more pushes can arrive: every accept thread joined above.
        let conns: Vec<(std::thread::JoinHandle<()>, WireStream)> =
            std::mem::take(&mut *self.conns.lock().unwrap());
        for (h, _) in conns {
            let _ = h.join();
        }
        if let Some(w) = self.maintenance.take() {
            w.shutdown();
        }
        #[cfg(unix)]
        if let Some(own) = self.unix_ownership.take() {
            Self::cleanup_unix_socket(&own);
        }
        if let Some(serving) = self.serving.take() {
            serving.store(false, Ordering::SeqCst);
        }
    }

    /// Stop and join everything (idempotent; `Drop` does the same).
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    /// Remove the Unix socket this owner created, only after re-verifying
    /// it still refers to the same socket inode. A missing path is already
    /// clean; a replaced path (different device/inode, non-socket, or
    /// unverifiable) is left alone, never blindly unlinked. Best-effort:
    /// an unlink error after a verified match leaves the file for the
    /// operator; ordinary tests verify removal in the normal case.
    #[cfg(unix)]
    fn cleanup_unix_socket(own: &UnixSocketOwnership) {
        use std::os::unix::fs::MetadataExt;
        let meta = match std::fs::symlink_metadata(&own.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => return,
        };
        if meta.dev() != own.dev || meta.ino() != own.ino {
            return;
        }
        if !meta.file_type().is_socket() {
            return;
        }
        let _ = std::fs::remove_file(&own.path);
    }
}

/// Load and validate token grants from a `tokens.json` file via
/// `crate::acl::TokenStore`. A missing file, invalid JSON, non-object
/// root, or malformed entry is an error (fail closed); set
/// `AGENT_BUS_OPEN=1` for the dev-only open mode instead. The diagnostic
/// never echoes token content (index-based `AclError` only).
pub fn load_tokens(path: &Path) -> std::io::Result<TokenStore> {
    let raw = std::fs::read(path)?;
    let text = std::str::from_utf8(&raw).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("tokens.json invalid: bad token root: invalid UTF-8: {e}"),
        )
    })?;
    TokenStore::from_json_str(text).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("tokens.json invalid: {e}"),
        )
    })
}

/// Dev-only open policy (mirrors `AGENT_BUS_OPEN=1`): the claimed name
/// with wildcard publish/subscribe grants. Never used off localhost.
fn open_policy(agent: &str) -> Policy {
    Policy::from_json(&json!({"agent": agent, "publish": ["*"], "subscribe": ["*"]}))
        .expect("open wildcard policy is valid")
}

#[derive(Clone)]
pub struct Server {
    state: Arc<Mutex<BusState>>,
    tokens: Arc<Mutex<TokenStore>>,
    tokens_path: Option<PathBuf>,
    tokens_raw: Arc<Mutex<Option<BTreeMap<String, Value>>>>,
    claim_log: Arc<Mutex<HashMap<String, Vec<f64>>>>,
    token_poison: Arc<Mutex<Option<String>>>,
    tokens_failpoint: Arc<AtomicU8>,
    wal_path: PathBuf,
    frame_limit: usize,
    open_mode: bool,
    // Exclusive WAL writer ownership, held for the server's lifetime: a
    // second broker process on the same WAL fails at startup instead of
    // replaying into a divergent copy. `None` only when the WAL parent is
    // missing (appends fail there anyway).
    _wal_lock: Option<WalLock>,
    // Memory-only presence roster, shared across connections (never WAL,
    // never cleared on disconnect; multiple conns for one agent share it).
    presence: Arc<Mutex<PresenceStore>>,
    // Test-only deterministic clock: `Some(t)` makes all post-auth
    // operations use `t` instead of system time (KV TTL/expiry, post
    // TTL, claim leases, fetch filtering, presence liveness/age/prune).
    // `None` (production) uses system time. Replay at construction still
    // uses system time; tests needing deterministic replay call
    // `wal::replay` directly. Shared via `Arc` so a held handle controls
    // the serving thread.
    fixed_now: Arc<Mutex<Option<f64>>>,
    // Test-only deterministic append failure injection (see
    // `wal::APPEND_FAIL_*`). Production is always `NONE`. Shared via
    // `Arc` like the clock.
    append_failpoint: Arc<AtomicU8>,
    // Fail-closed WAL poison: set when an `opened=true` append fails
    // and the truncate rollback also fails (possible partial bytes
    // that must not be concatenated onto). While poisoned, all
    // mutating ops fail with `wal poisoned` and reads stay available.
    // `None` means healthy.
    wal_poison: Arc<Mutex<Option<String>>>,
    // Boot timestamp for `stats.uptime_s` (legacy `stats["started"]`).
    // Set to system time after replay (matching legacy post-replay boot),
    // shared via `Arc` so introspection tests can pin it deterministically.
    started: Arc<Mutex<f64>>,
    // Live durable posts since boot (legacy `stats["posts"]`). Incremented
    // only after the WAL append+fsync succeeds, never for replayed history
    // or failed appends. Shared via `Arc` across serving threads.
    posts: Arc<AtomicU64>,
    // Live subscription table + delivery counters (legacy
    // `stats["deliveries"/"drops"/"replays"/"subs"]`). `subs` is a
    // registry mutex (state -> subs lock order, see `crate::subs`);
    // counters are lock-free so queue eviction never needs the registry
    // while holding a queue lock. `next_conn_id` mints per-connection
    // ownership ids.
    subs: Arc<Mutex<SubsRegistry>>,
    deliveries: Arc<AtomicU64>,
    drops: Arc<AtomicU64>,
    replays: Arc<AtomicU64>,
    next_conn_id: Arc<AtomicU64>,
    // Live post rate buckets + denial counter (legacy `rate_buckets` /
    // `stats["rate_limited"]`). Buckets are `(agent, rule)` in-memory
    // only (never WAL), shared across connections; denials increment
    // only on `rate exceeded` (never zero-filled gaps).
    rate_limiter: Arc<Mutex<RateLimiter>>,
    rate_limited: Arc<AtomicU64>,
    // Durable artifact bytes + quota/uploads (legacy `ART_DIR`,
    // `art_usage`, `uploads`; see `crate::artifacts`). Usage seeded
    // from WAL `art_own` at construction; staging cleaned there too.
    // Shared across connections; per-upload locks serialize one
    // upload without blocking others.
    artifacts: Arc<ArtifactStore>,
    // Test-only backpressure hooks (production: 2000/0, matching Python
    // `out_q` maxsize 2000 with an unthrottled writer). `subs_queue_max`
    // bounds new per-connection outboxes; `writer_delay_us` sleeps the
    // writer per frame to simulate a slow/non-reading peer
    // deterministically (socket backpressure alone needs tens of MB to
    // fill autotuned buffers). Shared via `Arc` so a held handle
    // controls the serving thread; only affects connections accepted
    // after the set (existing outboxes keep their capacity).
    subs_queue_max: Arc<std::sync::atomic::AtomicUsize>,
    writer_delay_us: Arc<AtomicU64>,
    // Owned-lifecycle guard: true while an `OwnedBroker` from
    // `serve_owned` is live (set at start, cleared only after the full
    // stop-and-join). Rejects a duplicate accept loop + maintenance
    // worker on one `Server`; sequential start/stop/start is allowed.
    // Legacy `serve` never touches this flag.
    serving: Arc<AtomicBool>,
}

impl Server {
    /// Establish writer ownership, then replay the WAL and fail closed on
    /// corruption: a broker that cannot faithfully restore history must not
    /// start empty, and two broker processes must never share one WAL.
    /// After a clean replay the tail is repaired (torn partial bytes
    /// truncated, or a missing newline appended after a complete final
    /// record) so the first new append cannot concatenate onto unrepaired
    /// bytes; a repair failure also refuses startup. A legacy `kv.json`
    /// snapshot sibling refuses startup explicitly (never silently
    /// discarded): native durability is WAL-only.
    pub fn new(wal_path: PathBuf, tokens: TokenStore) -> Result<Self, ReplayError> {
        let wal_lock = acquire_wal_lock(&wal_path).map_err(ReplayError::Open)?;
        let snapshot = snapshot_path_for(&wal_path);
        if snapshot.exists() {
            return Err(ReplayError::Open(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unsupported legacy KV snapshot at {}: refusing to start so snapshot-only keys are never silently discarded (migrate to WAL-only or remove after backup)",
                    snapshot.display()
                ),
            )));
        }
        let mut state = BusState::new();
        replay(&wal_path, &mut state, now())?;
        crate::wal::repair_tail(&wal_path).map_err(ReplayError::Open)?;
        let art_usage = crate::wal::replay_art_usage(&wal_path)?;
        let art_dir = wal_path
            .parent()
            .map(|p| p.join("artifacts"))
            .unwrap_or_else(|| PathBuf::from("artifacts"));
        let artifacts = ArtifactStore::new(art_dir)
            .map_err(|e| ReplayError::Open(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        for (agent, size) in art_usage {
            artifacts.restore_usage(&agent, size);
        }
        Ok(Server {
            state: Arc::new(Mutex::new(state)),
            tokens: Arc::new(Mutex::new(tokens)),
            tokens_path: None,
            tokens_raw: Arc::new(Mutex::new(None)),
            claim_log: Arc::new(Mutex::new(HashMap::new())),
            token_poison: Arc::new(Mutex::new(None)),
            tokens_failpoint: Arc::new(AtomicU8::new(crate::tokens::TOKENS_FAIL_NONE)),
            wal_path,
            frame_limit: FRAME_LIMIT,
            open_mode: false,
            _wal_lock: wal_lock,
            presence: Arc::new(Mutex::new(PresenceStore::new())),
            fixed_now: Arc::new(Mutex::new(None)),
            append_failpoint: Arc::new(AtomicU8::new(APPEND_FAIL_NONE)),
            wal_poison: Arc::new(Mutex::new(None)),
            started: Arc::new(Mutex::new(now())),
            posts: Arc::new(AtomicU64::new(0)),
            subs: Arc::new(Mutex::new(SubsRegistry::new())),
            deliveries: Arc::new(AtomicU64::new(0)),
            drops: Arc::new(AtomicU64::new(0)),
            replays: Arc::new(AtomicU64::new(0)),
            next_conn_id: Arc::new(AtomicU64::new(1)),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
            rate_limited: Arc::new(AtomicU64::new(0)),
            artifacts: Arc::new(artifacts),
            subs_queue_max: Arc::new(std::sync::atomic::AtomicUsize::new(SUBS_QUEUE_MAX)),
            writer_delay_us: Arc::new(AtomicU64::new(0)),
            serving: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Durable artifact directory (`<wal-parent>/artifacts`).
    /// Tests use it to chmod/inspect without touching live paths.
    pub fn artifacts_dir(&self) -> PathBuf {
        self.artifacts.dir().to_path_buf()
    }

    /// Dev-only open mode (mirrors `AGENT_BUS_OPEN=1`): any non-empty agent
    /// name is accepted with wildcard grants. Never enable off localhost.
    pub fn with_open_mode(mut self, open: bool) -> Self {
        self.open_mode = open;
        self
    }

    /// Test hook: shrink the inbound frame cap (production uses FRAME_LIMIT).
    pub fn with_frame_limit(mut self, limit: usize) -> Self {
        self.frame_limit = limit;
        self
    }

    /// Configure the durable token-file path (`--tokens` /
    /// `AGENT_BUS_TOKENS`). `None` (default, all pre-token tests) refuses
    /// token mutations post-auth (`token persistence not configured`);
    /// file-backed servers persist every issue/revoke/claim atomically.
    /// Raw entries lazy-load verbatim on first mutation (no churn for
    /// existing entries beyond sorted pretty-print).
    pub fn with_tokens_path(mut self, path: PathBuf) -> Self {
        self.tokens_path = Some(path);
        self
    }

    /// Test hook: set the token-persist failure injection mode (see
    /// `tokens::TOKENS_FAIL_*`). Shared with the serving thread. Always
    /// `NONE` in production.
    pub fn set_tokens_failpoint(&self, mode: u8) {
        self.tokens_failpoint.store(mode, Ordering::SeqCst);
    }

    /// Current token-store poison reason, if a post-rename dir-fsync
    /// failure left the destination uncertain. While poisoned, token
    /// mutations refuse; hello/auth reads stay available.
    pub fn token_poisoned(&self) -> Option<String> {
        self.token_poison.lock().unwrap().clone()
    }

    /// Test hook: poison the token store directly. Production never calls
    /// this; real poison comes only from post-rename uncertainty.
    pub fn poison_tokens_for_test(&self, reason: &str) {
        *self.token_poison.lock().unwrap() = Some(reason.to_string());
    }

    /// Test hook: pin the server clock to `Some(t)` (deterministic TTL/
    /// expiry/lease tests) or restore system time with `None`.
    /// Shared with the serving thread via `Arc`, so a held handle
    /// controls live operations. Replay at construction already used
    /// system time.
    pub fn set_fixed_now(&self, now: Option<f64>) {
        *self.fixed_now.lock().unwrap() = now;
    }

    /// Test hook: set the append failure injection mode (see
    /// `wal::APPEND_FAIL_*`). Shared with the serving thread. Always
    /// `NONE` in production.
    pub fn set_append_failpoint(&self, mode: u8) {
        self.append_failpoint.store(mode, Ordering::SeqCst);
    }

    /// Current poison reason, if the WAL was poisoned by a failed
    /// rollback after an `opened=true` append failure.
    pub fn wal_poisoned(&self) -> Option<String> {
        self.wal_poison.lock().unwrap().clone()
    }

    /// Test hook: poison the WAL directly (proves fail-closed reads
    /// stay available while mutations refuse). Production never calls
    /// this; real poison comes only from failed rollback.
    pub fn poison_for_test(&self, reason: &str) {
        *self.wal_poison.lock().unwrap() = Some(reason.to_string());
    }

    /// Test hook: fail the next `n` owned-staging unlinks
    /// (`disconnect`/`art_commit`/`art_abort` via
    /// `ArtifactStore::unlink_staging_owned`). Each injected failure is
    /// counted in `stats.staging_cleanup_failed` and retains the upload
    /// for explicit `art_abort` retry (bounded, no background workers).
    /// Production never sets this (always 0). Shared via `Arc`, so a
    /// held handle controls live operations without timing races or
    /// permission tricks that silently change under UID 0.
    pub fn set_artifact_unlink_failpoint_for_test(&self, n: u64) {
        self.artifacts.set_unlink_failpoint_for_test(n);
    }

    /// Test hook: replace the artifact staging admission bounds
    /// (deterministic tiny-limit tests; see
    /// `crate::artifacts::StagingLimits`). Existing reservations are
    /// grandfathered; the new bounds gate subsequent `art_init`
    /// admissions. Production never calls this (compiled defaults).
    /// Shared via `Arc`, so a held handle controls live admissions.
    pub fn set_staging_limits_for_test(&self, limits: crate::artifacts::StagingLimits) {
        self.artifacts.set_staging_limits_for_test(limits);
    }

    /// Boot timestamp backing `stats.started`/`uptime_s` (legacy
    /// `stats["started"]`, set after replay). Shared with the serving
    /// thread; production never mutates it after construction.
    pub fn started(&self) -> f64 {
        *self.started.lock().unwrap()
    }

    /// Test hook: pin the boot timestamp for deterministic `uptime_s`
    /// (production uses the post-replay system time). Shared via `Arc`.
    pub fn set_started_for_test(&self, started: f64) {
        *self.started.lock().unwrap() = started;
    }

    /// Test hook: bound new per-connection outboxes to `max` frames
    /// (production: [`SUBS_QUEUE_MAX`]). Only affects connections
    /// accepted after the set; existing outboxes keep their capacity.
    /// Combined with [`Server::set_writer_delay_for_test`], simulates a
    /// slow/non-reading peer deterministically with small payloads.
    pub fn set_subs_queue_max_for_test(&self, max: usize) {
        self.subs_queue_max
            .store(max.max(1), std::sync::atomic::Ordering::SeqCst);
    }

    /// Test hook: sleep the writer `micros` per frame (production: 0).
    /// Simulates a slow peer without filling autotuned socket buffers
    /// (which need tens of MB). Shared via `Arc`; affects all writers.
    pub fn set_writer_delay_for_test(&self, micros: u64) {
        self.writer_delay_us.store(micros, Ordering::SeqCst);
    }

    /// Test hook: hold/release the writer for `sub_id`'s connection
    /// (deterministic backpressure without timing races). While held,
    /// that writer blocks before each pop; other connections drain
    /// normally. Production never holds. Returns false when unknown.
    pub fn set_sub_hold_for_test(&self, sub_id: &str, hold: bool) -> bool {
        let outbox = {
            let subs = self.subs.lock().unwrap();
            subs.get(sub_id).map(|s| std::sync::Arc::clone(&s.outbox))
        };
        match outbox {
            Some(ob) => {
                ob.set_hold(hold);
                true
            }
            None => false,
        }
    }

    /// Test hook: synchronous queue depth for `sub_id`'s connection
    /// (no RPC drain window). Returns `None` when unknown.
    pub fn subs_queued_for_test(&self, sub_id: &str) -> Option<usize> {
        let subs = self.subs.lock().unwrap();
        subs.get(sub_id).map(|s| s.outbox.len())
    }

    /// Test hook: capture the shared outbox for `sub_id`'s connection
    /// (to observe/release the hold after the sub itself is removed,
    /// when [`Server::set_sub_hold_for_test`] can no longer resolve it).
    /// Production never calls this. Returns `None` when unknown.
    pub fn outbox_for_test(&self, sub_id: &str) -> Option<std::sync::Arc<ConnOutbox>> {
        let subs = self.subs.lock().unwrap();
        subs.get(sub_id).map(|s| std::sync::Arc::clone(&s.outbox))
    }

    /// Live durable posts since boot backing `stats.posts` (legacy
    /// `stats["posts"]`, replay-excluded). Incremented only on durable
    /// `post` success.
    pub fn posts(&self) -> u64 {
        self.posts.load(Ordering::SeqCst)
    }

    /// Live delivery counters backing `stats.deliveries`/`drops`/
    /// `replays` (legacy names). `deliveries` counts live frames queued
    /// (replay excluded); `drops` counts live evicted/dropped (oldest
    /// evicted + new dropped, including pending overflow and reliable
    /// evictions); `replays` counts replay frames queued.
    pub fn deliveries(&self) -> u64 {
        self.deliveries.load(Ordering::SeqCst)
    }

    pub fn drops(&self) -> u64 {
        self.drops.load(Ordering::SeqCst)
    }

    pub fn replays(&self) -> u64 {
        self.replays.load(Ordering::SeqCst)
    }

    /// Live subscription count backing `stats.subs`.
    pub fn subs_len(&self) -> usize {
        self.subs.lock().unwrap().len()
    }

    /// Live post rate denials since boot backing `stats.rate_limited`
    /// (legacy `stats["rate_limited"]`). Incremented only on `rate
    /// exceeded`, never for allowed/denied/unlimited posts.
    pub fn rate_limited(&self) -> u64 {
        self.rate_limited.load(Ordering::SeqCst)
    }

    /// One bounded idle-expiry pass at the server clock (`fixed_now` when
    /// pinned, else system time). Releases expired topic payloads
    /// (`history::Topic::expire`, `now > exp`, high-water kept), expired KV
    /// (`KvStore::purge_expired`, `now > exp`), expired leases
    /// (`ClaimStore::purge_expired_at`, `now >= expires_at`, receipts kept),
    /// and stale presence/retired (`PresenceStore::prune`). Empty topics are
    /// kept (never removed from the map) so cursors/gaps/idempotency keep
    /// their high-water identity. Request-time filtering is unchanged: fetch,
    /// subscribe replay, `topics`, `kv_get`/`kv_list`, and `find_live_by_id`
    /// already exclude expired, so a tick never changes observable wire
    /// results, only memory. No WAL/filesystem IO; each lock is held briefly
    /// (topic names collected under a short lock, then each topic expired
    /// under its own short lock so concurrent posts interleave; KV, leases,
    /// and presence each under their own short lock; leases via a cloned
    /// handle so the global state lock is not held across the claims lock).
    /// Non-finite `now` is a no-op returning an empty report (fail closed,
    /// never mass-drop). Deterministic under `set_fixed_now`; production
    /// workers call this every 5s (legacy parity), giving eventual cleanup
    /// latency of about one interval, not immediate release and not a hard
    /// memory cap (concurrent inserts grow between ticks).
    pub fn maintenance_tick(&self) -> MaintenanceReport {
        self.maintenance_tick_at(self.clock_now())
    }

    /// One bounded idle-expiry pass at explicit `now` (deterministic hook;
    /// same semantics as [`Server::maintenance_tick`] without reading the
    /// server clock). Non-finite `now` is a no-op.
    pub fn maintenance_tick_at(&self, now: f64) -> MaintenanceReport {
        let mut report = MaintenanceReport::default();
        if !now.is_finite() {
            return report;
        }
        // Topics: collect names under a short lock, then expire each under
        // its own short lock (bounded per-topic work: at most
        // RETAIN_PER_TOPIC msgs; global lock released between topics).
        let names: Vec<String> = {
            let state = self.state.lock().unwrap();
            let mut v: Vec<String> = state.topics.keys().cloned().collect();
            v.sort();
            v
        };
        report.topics_scanned = names.len();
        for name in names {
            let mut state = self.state.lock().unwrap();
            if let Some(t) = state.topics.get_mut(&name) {
                let before = t.msgs.len();
                t.expire(now);
                report.msgs_removed += before.saturating_sub(t.msgs.len());
            }
        }
        // KV: single short lock, existing purge (no second expiry model).
        {
            let mut state = self.state.lock().unwrap();
            report.kv_removed = state.kv.purge_expired(now);
        }
        // Leases: clone the Arc handle under a short lock, then purge without
        // holding global state (avoids state->claims nesting; same predicate).
        {
            let claims = self.state.lock().unwrap().claims.clone();
            report.leases_removed = claims.purge_expired_at(now);
        }
        // Presence/retired: single short lock, existing prune.
        {
            let mut p = self.presence.lock().unwrap();
            let before_agents = p.len();
            let before_retired = p.retired_len();
            p.prune(now);
            report.presence_removed = before_agents.saturating_sub(p.len());
            report.retired_removed = before_retired.saturating_sub(p.retired_len());
        }
        report
    }

    /// Stored topic payload count for `topic` including expired-but-not-purged
    /// (test introspection; fetch/`topics` already filter expired). Returns
    /// `(high_water_seq, stored_msgs)` or `None` when the topic never existed.
    /// Empty-after-expiry topics still report `(seq, 0)` (high-water kept).
    pub fn topic_stored_for_test(&self, topic: &str) -> Option<(u64, usize)> {
        let state = self.state.lock().unwrap();
        state.topics.get(topic).map(|t| (t.seq, t.msgs.len()))
    }

    /// Stored KV count including expired-but-not-purged (test introspection;
    /// `kv_get`/`kv_list`/`stats.kv_keys` already filter to live).
    pub fn kv_stored_len_for_test(&self) -> usize {
        self.state.lock().unwrap().kv.len()
    }

    /// Stored lease count including expired-but-not-purged (test
    /// introspection; claim ops already treat expired as gone).
    pub fn leases_stored_len_for_test(&self) -> usize {
        self.state.lock().unwrap().claims.stored_len()
    }

    /// Presence counts including stale-but-not-pruned: `(agents, retired)`
    /// (test introspection; `agents`/`stats` already prune at request time).
    pub fn presence_stored_len_for_test(&self) -> (usize, usize) {
        let p = self.presence.lock().unwrap();
        (p.len(), p.retired_len())
    }

    /// Live subscription count (test introspection; disconnect cleanup
    /// removes owned subs, so an owned-broker shutdown drains this to 0).
    pub fn subs_len_for_test(&self) -> usize {
        self.subs.lock().unwrap().len()
    }

    /// Test hook: retire `agent` at the server clock (pops presence, suppresses
    /// re-add for 1h, matching `token_claim` retirement without needing claim
    /// auth). Production never calls this (real retirement comes only from
    /// `token_claim`). Non-finite clocks are a no-op.
    pub fn retire_presence_for_test(&self, agent: &str) {
        let now = self.clock_now();
        if !now.is_finite() {
            return;
        }
        self.presence.lock().unwrap().retire(agent, now);
    }

    /// Spawn one lifecycle-owned idle worker ticking
    /// [`Server::maintenance_tick`] every `interval` (sleep-first, then tick).
    /// The returned guard owns the thread: dropping/`shutdown` signals stop
    /// and joins (clean shutdown, no detached thread, no per-topic threads).
    /// Stop wakes the interval wait; an already-running tick finishes first.
    /// Production `serve` wrappers hold the guard for the broker lifetime
    /// with [`MAINTENANCE_INTERVAL_DEFAULT`]; tests hold it briefly with a
    /// short interval or use explicit ticks. Zero intervals tick without
    /// sleeping (tests only; production uses 5s).
    pub fn spawn_maintenance_worker(&self, interval: std::time::Duration) -> MaintenanceWorker {
        let srv = self.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = Arc::clone(&stop);
        let (wake, wake_rx) = std::sync::mpsc::sync_channel(1);
        let handle = std::thread::spawn(move || loop {
            if interval.is_zero() {
                std::thread::yield_now();
            }
            match wake_rx.recv_timeout(interval) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            if stop_w.load(Ordering::SeqCst) {
                break;
            }
            let _ = srv.maintenance_tick();
        });
        MaintenanceWorker {
            stop,
            wake,
            handle: Some(handle),
        }
    }

    fn clock_now(&self) -> f64 {
        self.fixed_now.lock().unwrap().unwrap_or_else(now)
    }

    fn poisoned_error(&self) -> Option<String> {
        self.wal_poison
            .lock()
            .unwrap()
            .clone()
            .map(|r| format!("wal poisoned: {r}"))
    }

    fn pre_len(&self) -> Result<u64, String> {
        pre_append_len(&self.wal_path)
    }

    /// Robust value append: detailed failure injection, truncate rollback
    /// on `opened=true`, poison when rollback fails. Returns `Ok` on
    /// durable success, `Err(message)` with `wal append failed` (rolled
    /// back, safe to continue) or `wal poisoned` (fail-closed). A
    /// pre-length metadata error other than missing file fails before any
    /// bytes are written (never a truncate-to-zero authorization).
    fn append_value_robust(&self, value: &Value) -> Result<(), String> {
        if let Some(p) = self.poisoned_error() {
            return Err(p);
        }
        let pre = self.pre_len()?;
        let fail = self.append_failpoint.load(Ordering::SeqCst);
        match append_fsync_detailed(&self.wal_path, value, fail) {
            Ok(()) => Ok(()),
            Err(e) if !e.opened => Err(format!("wal append failed: {}", e.source)),
            Err(e) => match truncate_to(&self.wal_path, pre) {
                Ok(()) => Err(format!("wal append failed: {}", e.source)),
                Err(te) => {
                    let reason = format!(
                        "append failed ({}) and rollback to {pre} failed ({te})",
                        e.source
                    );
                    *self.wal_poison.lock().unwrap() = Some(reason.clone());
                    Err(format!("wal poisoned: {reason}"))
                }
            },
        }
    }

    /// Robust pre-rendered line append (KV durability callback).
    /// Same rollback/poison discipline as [`Server::append_value_robust`].
    fn append_line_robust(&self, line: &str) -> Result<(), String> {
        if let Some(p) = self.poisoned_error() {
            return Err(p);
        }
        let pre = self.pre_len()?;
        let fail = self.append_failpoint.load(Ordering::SeqCst);
        match append_line_fsync_detailed(&self.wal_path, line, fail) {
            Ok(()) => Ok(()),
            Err(e) if !e.opened => Err(format!("wal append failed: {}", e.source)),
            Err(e) => match truncate_to(&self.wal_path, pre) {
                Ok(()) => Err(format!("wal append failed: {}", e.source)),
                Err(te) => {
                    let reason = format!(
                        "append failed ({}) and rollback to {pre} failed ({te})",
                        e.source
                    );
                    *self.wal_poison.lock().unwrap() = Some(reason.clone());
                    Err(format!("wal poisoned: {reason}"))
                }
            },
        }
    }

    /// Legacy detached serve: blocks on the accept loop forever, spawning
    /// one unjoined handler thread per connection (each handler still owns
    /// and joins its own writer). Kept for existing tests; new code and
    /// the native `serve` CLI use [`Server::serve_owned`], which owns the
    /// accept loop, every connection thread, and the maintenance worker
    /// with explicit stop/join.
    pub fn serve(&self, listener: TcpListener) {
        for stream in listener.incoming().flatten() {
            let this = self.clone();
            std::thread::spawn(move || this.handle(WireStream::Tcp(stream)));
        }
    }

    /// Serve `listener` (TCP-only) with an owned lifecycle: returns an
    /// [`OwnedBroker`] owning the accept thread, every admitted connection
    /// thread, and one idle maintenance worker ticking every
    /// `maintenance_interval`. The native `serve` CLI uses this when no
    /// Unix socket is configured (with [`MAINTENANCE_INTERVAL_DEFAULT`]).
    ///
    /// Fails without starting anything when this `Server` already has a
    /// live `OwnedBroker` (no duplicate accept loops or maintenance
    /// workers), or when the listener cannot be made non-blocking.
    /// Preserved TCP behavior: existing callers keep working unchanged.
    pub fn serve_owned(
        &self,
        listener: TcpListener,
        maintenance_interval: std::time::Duration,
    ) -> Result<OwnedBroker, String> {
        if self
            .serving
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("broker already serving: stop the live OwnedBroker first".to_string());
        }
        if let Err(e) = listener.set_nonblocking(true) {
            self.serving.store(false, Ordering::SeqCst);
            return Err(format!("owned serve: cannot set non-blocking accept: {e}"));
        }
        let maintenance = self.spawn_maintenance_worker(maintenance_interval);
        let stop = Arc::new(AtomicBool::new(false));
        let conns: ConnRegistry = Arc::new(Mutex::new(Vec::new()));
        let this = self.clone();
        let stop_a = Arc::clone(&stop);
        let conns_a = Arc::clone(&conns);
        let accept = std::thread::spawn(move || Self::accept_loop(this, listener, stop_a, conns_a));
        Ok(OwnedBroker {
            serving: Some(Arc::clone(&self.serving)),
            stop,
            accept: vec![accept],
            conns,
            maintenance: Some(maintenance),
            #[cfg(unix)]
            unix_ownership: None,
        })
    }

    /// Serve one Unix socket `path` with an owned lifecycle (only on
    /// `cfg(unix)`): binds the socket, records ownership, and returns an
    /// [`OwnedBroker`] owning the accept thread, every connection, and
    /// maintenance. Fails without creating anything when this `Server`
    /// already serves, when `path` already exists (any file type: never
    /// blindly unlinked), or when bind/non-blocking fails. The socket is
    /// removed at [`OwnedBroker::stop_and_join`]/drop only after
    /// re-verifying it still matches.
    #[cfg(unix)]
    pub fn serve_owned_unix(
        &self,
        path: &Path,
        maintenance_interval: std::time::Duration,
    ) -> Result<OwnedBroker, String> {
        if self
            .serving
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("broker already serving: stop the live OwnedBroker first".to_string());
        }
        let (listener, ownership) = match Self::bind_unix_socket(path) {
            Ok(v) => v,
            Err(e) => {
                self.serving.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };
        if let Err(e) = listener.set_nonblocking(true) {
            self.serving.store(false, Ordering::SeqCst);
            Self::remove_just_bound(path, &ownership);
            return Err(format!(
                "owned serve: cannot set non-blocking unix accept: {e}"
            ));
        }
        let maintenance = self.spawn_maintenance_worker(maintenance_interval);
        let stop = Arc::new(AtomicBool::new(false));
        let conns: ConnRegistry = Arc::new(Mutex::new(Vec::new()));
        let this = self.clone();
        let stop_a = Arc::clone(&stop);
        let conns_a = Arc::clone(&conns);
        let accept =
            std::thread::spawn(move || Self::accept_loop_unix(this, listener, stop_a, conns_a));
        Ok(OwnedBroker {
            serving: Some(Arc::clone(&self.serving)),
            stop,
            accept: vec![accept],
            conns,
            maintenance: Some(maintenance),
            unix_ownership: Some(ownership),
        })
    }

    /// Serve TCP `listener` plus Unix `unix_path` simultaneously with ONE
    /// owner (only on `cfg(unix)`): two accept threads, one shared
    /// connection registry, one maintenance worker, one serving guard.
    /// Matches the legacy transitional broker, which always listens on
    /// both `HOST:PORT` and `AGENT_BUS_SOCK`. Fails without starting
    /// anything when already serving, when `unix_path` already exists, or
    /// when either listener cannot be prepared; a Unix socket bound just
    /// before a later failure is removed again (it is still ours).
    #[cfg(unix)]
    pub fn serve_owned_dual(
        &self,
        tcp_listener: TcpListener,
        unix_path: &Path,
        maintenance_interval: std::time::Duration,
    ) -> Result<OwnedBroker, String> {
        if self
            .serving
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("broker already serving: stop the live OwnedBroker first".to_string());
        }
        if let Err(e) = tcp_listener.set_nonblocking(true) {
            self.serving.store(false, Ordering::SeqCst);
            return Err(format!(
                "owned serve: cannot set non-blocking tcp accept: {e}"
            ));
        }
        let (unix_listener, ownership) = match Self::bind_unix_socket(unix_path) {
            Ok(v) => v,
            Err(e) => {
                self.serving.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };
        if let Err(e) = unix_listener.set_nonblocking(true) {
            self.serving.store(false, Ordering::SeqCst);
            Self::remove_just_bound(unix_path, &ownership);
            return Err(format!(
                "owned serve: cannot set non-blocking unix accept: {e}"
            ));
        }
        let maintenance = self.spawn_maintenance_worker(maintenance_interval);
        let stop = Arc::new(AtomicBool::new(false));
        let conns: ConnRegistry = Arc::new(Mutex::new(Vec::new()));
        let this_tcp = self.clone();
        let stop_tcp = Arc::clone(&stop);
        let conns_tcp = Arc::clone(&conns);
        let accept_tcp = std::thread::spawn(move || {
            Self::accept_loop(this_tcp, tcp_listener, stop_tcp, conns_tcp)
        });
        let this_unix = self.clone();
        let stop_unix = Arc::clone(&stop);
        let conns_unix = Arc::clone(&conns);
        let accept_unix = std::thread::spawn(move || {
            Self::accept_loop_unix(this_unix, unix_listener, stop_unix, conns_unix)
        });
        Ok(OwnedBroker {
            serving: Some(Arc::clone(&self.serving)),
            stop,
            accept: vec![accept_tcp, accept_unix],
            conns,
            maintenance: Some(maintenance),
            unix_ownership: Some(ownership),
        })
    }

    /// Bind a Unix socket at `path`, refusing when anything already exists
    /// there. Returns the listener plus ownership evidence (device/inode
    /// after bind). Never unlinks a pre-existing path. On post-bind
    /// metadata failure or a non-socket result, ownership is uncertain:
    /// leave the pathname untouched and return an error. Dropping the
    /// listener closes our descriptor; an operator may need to inspect
    /// the remaining pathname before retrying.
    #[cfg(unix)]
    fn bind_unix_socket(path: &Path) -> Result<(UnixListener, UnixSocketOwnership), String> {
        use std::os::unix::fs::MetadataExt;
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(format!(
                    "unix socket path already exists: {}: refusing to remove; remove it or choose another path",
                    path.display()
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!(
                    "cannot check unix socket path {}: {e}",
                    path.display()
                ));
            }
        }
        let listener = UnixListener::bind(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                format!(
                    "unix socket path already in use: {}: refusing to remove; remove it or choose another path",
                    path.display()
                )
            } else {
                format!("cannot bind unix socket {}: {e}", path.display())
            }
        })?;
        let meta = std::fs::symlink_metadata(path).map_err(|e| {
            format!(
                "cannot verify just-bound unix socket {}: {e}; pathname left untouched",
                path.display()
            )
        })?;
        if !meta.file_type().is_socket() {
            return Err(format!(
                "just-bound unix path is not a socket: {}; pathname left untouched",
                path.display()
            ));
        }
        Ok((
            listener,
            UnixSocketOwnership {
                path: path.to_path_buf(),
                dev: meta.dev(),
                ino: meta.ino(),
            },
        ))
    }

    /// Remove a socket bound moments ago in this same startup path, after
    /// re-verifying it still matches (same device/inode, still a socket).
    /// Used only when a later startup step fails before serving began.
    #[cfg(unix)]
    fn remove_just_bound(path: &Path, own: &UnixSocketOwnership) {
        use std::os::unix::fs::MetadataExt;
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };
        if meta.dev() != own.dev || meta.ino() != own.ino {
            return;
        }
        if !meta.file_type().is_socket() {
            return;
        }
        let _ = std::fs::remove_file(path);
    }

    /// Owned TCP accept loop (runs on one of [`OwnedBroker`]'s accept
    /// threads): admits peers until `stop`, registering every spawned
    /// handler with a shutdown clone of its socket. On stop the listener
    /// is dropped (kernel stops admitting) and every registered socket is
    /// shut down so each reader sees EOF and runs normal disconnect
    /// cleanup. Preserved TCP behavior; shared with dual (TCP+Unix) mode.
    fn accept_loop(
        server: Server,
        listener: TcpListener,
        stop: Arc<AtomicBool>,
        conns: ConnRegistry,
    ) {
        loop {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    // Stop admitting the moment shutdown started: a peer
                    // accepted in the race is dropped, never served.
                    if stop.load(Ordering::SeqCst) {
                        drop(stream);
                        break;
                    }
                    // Register the shutdown clone BEFORE spawning so every
                    // spawned handler is guaranteed unblockable at shutdown.
                    let wire = WireStream::Tcp(stream);
                    let shutdown_clone = match wire.try_clone() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let this = server.clone();
                    let h = std::thread::spawn(move || this.handle(wire));
                    let mut guard = conns.lock().unwrap();
                    guard.push((h, shutdown_clone));
                    // Reap finished handlers (+ their fds) once the registry
                    // outgrows live use; dropping a finished `JoinHandle`
                    // cleanly detaches an already-exited thread.
                    if guard.len() > 64 {
                        guard.retain(|(h, _)| !h.is_finished());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    // Like legacy `serve` (`.flatten()`), a failed accept is
                    // skipped, never fatal; sleep so a persistent error
                    // cannot hot-spin, and re-check stop promptly.
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(ACCEPT_POLL);
                }
            }
        }
        // Stop admitting: drop the listener first so the kernel refuses new
        // peers, then unblock every admitted reader so each handler runs
        // its normal disconnect cleanup and becomes joinable.
        drop(listener);
        for (_, s) in conns.lock().unwrap().iter() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    /// Owned Unix accept loop (only on `cfg(unix)`): same contract as
    /// [`Server::accept_loop`] but for `UnixListener`/`UnixStream`. In
    /// dual mode both loops share one stop flag, one connection registry,
    /// and one owner; each drops its own listener on stop and shuts the
    /// shared registry down (idempotent across the two threads).
    #[cfg(unix)]
    fn accept_loop_unix(
        server: Server,
        listener: UnixListener,
        stop: Arc<AtomicBool>,
        conns: ConnRegistry,
    ) {
        loop {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if stop.load(Ordering::SeqCst) {
                        drop(stream);
                        break;
                    }
                    let wire = WireStream::Unix(stream);
                    let shutdown_clone = match wire.try_clone() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let this = server.clone();
                    let h = std::thread::spawn(move || this.handle(wire));
                    let mut guard = conns.lock().unwrap();
                    guard.push((h, shutdown_clone));
                    if guard.len() > 64 {
                        guard.retain(|(h, _)| !h.is_finished());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(ACCEPT_POLL);
                }
            }
        }
        drop(listener);
        for (_, s) in conns.lock().unwrap().iter() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    fn handle(&self, stream: WireStream) {
        // Per-connection ownership id + bounded outbox (shared-queue
        // semantics, matching Python `out_q` maxsize 2000). The writer
        // thread owns one socket clone; this reader owns the other.
        // Cleanup always removes owned subs, closes the outbox, and joins
        // the writer (no detached/leaked writers). Shared across TCP and
        // Unix: framing/auth/ACL/history/durability/state are identical.
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::SeqCst);
        let cap = self
            .subs_queue_max
            .load(std::sync::atomic::Ordering::SeqCst)
            .max(1);
        let outbox = std::sync::Arc::new(ConnOutbox::new(cap));
        let writer_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let outbox_w = std::sync::Arc::clone(&outbox);
        let delay = std::sync::Arc::clone(&self.writer_delay_us);
        let subs_w = std::sync::Arc::clone(&self.subs);
        let clock_w = std::sync::Arc::clone(&self.fixed_now);
        let drops_w = std::sync::Arc::clone(&self.drops);
        let writer_join = std::thread::spawn(move || {
            writer_loop(
                writer_stream,
                outbox_w,
                delay,
                subs_w,
                conn_id,
                clock_w,
                drops_w,
            )
        });
        let mut reader = BufReader::new(stream);
        // Internal-only peer label (never wire-visible; TCP `SocketAddr`
        // text differs from Python tuple `str`, Unix uses `unix[:path]`;
        // stored for parity only).
        let peer = reader.get_ref().peer_label();
        let limit = self.frame_limit;
        let mut auth: Option<(String, String, Policy)> = None;
        // Pending uploads initiated on this connection (legacy
        // `my_uploads`, `broker.py:800`): aborted + unlinked on
        // disconnect (never surviving the owner conn or a restart).
        // Clean commit/abort pops end ownership; a commit reporting
        // `ok` plus `staging_cleanup_error` retains it so disconnect
        // attempts the pending unlink once (bounded, no workers).
        let mut my_uploads: std::collections::HashSet<String> = std::collections::HashSet::new();
        // True when the loop broke for a protocol error where the peer is
        // still connected and must receive the terminal error (drain),
        // vs EOF/writer-death where the peer is gone (discard).
        let mut drain_close = false;
        loop {
            let line = match read_frame(&mut reader, limit) {
                FrameRead::Line(l) => l,
                FrameRead::Eof => break,
                FrameRead::BadUtf8 => {
                    let frame = json!({"req_id": Value::Null, "error": "frame is not valid UTF-8"});
                    if outbox.push_control(frame, &self.drops).is_err() {
                        break;
                    }
                    continue;
                }
                FrameRead::TooLarge => {
                    // Mirrors the Python reader limit: oversize input drops
                    // the connection instead of consuming memory. Native
                    // sends the explicit null-id error first (preserved
                    // `wire::Client` frame-error protocol; Python just
                    // drops). Discard stale live so the error is not delayed
                    // behind 2000 live frames, preserve reliable order, then
                    // drain (peer is still connected and reading).
                    self.subs.lock().unwrap().remove_conn(conn_id);
                    outbox.retain_reliable();
                    let frame = json!({"req_id": Value::Null, "error": "frame exceeds byte limit"});
                    let _ = outbox.push_control(frame, &self.drops);
                    drain_close = true;
                    break;
                }
            };
            let fr: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let req_id = fr.get("req_id").cloned().unwrap_or(Value::Null);
            let op = fr.get("op").and_then(|o| o.as_str()).unwrap_or("");
            // Prompt revocation enforcement: every authed op (except
            // `hello`/`ping`, which handle themselves) re-checks the hello
            // token against the live store before liveness/dispatch.
            // Revoked/expired clears auth and fails with the hello string
            // (no silent stale creds). Open mode skips (no real store).
            // Non-finite clocks skip the expiry check here (presence-only);
            // ops with their own clock gate still fail `non-finite time`,
            // while clock-free ops (`limits`) preserve existing behavior.
            if op != "hello" && op != "ping" {
                if let Some((agent, token, _)) = auth.clone() {
                    if !self.open_mode {
                        let now = self.clock_now();
                        match self.revalidate_token(&agent, &token, now) {
                            Ok(fresh) => {
                                // Narrowed grants prune immediately (same
                                // token, new policy): survivors refresh.
                                {
                                    let mut subs = self.subs.lock().unwrap();
                                    subs.set_conn_auth(conn_id, &token, &fresh);
                                    subs.prune_conn_for_policy(
                                        conn_id,
                                        &fresh,
                                        &outbox,
                                        &self.drops,
                                    );
                                }
                                auth = Some((agent.clone(), token, fresh));
                            }
                            Err(msg) => {
                                // Auth boundary: drop stale subs + queued
                                // live (counted), preserve reliable, then
                                // the error receipt (never stale live).
                                self.subs.lock().unwrap().remove_conn(conn_id);
                                outbox.purge_live_with_accounting(&self.drops);
                                auth = None;
                                let frame = with_req_id(&req_id, &json!({"error": msg}));
                                if outbox.push_control(frame, &self.drops).is_err() {
                                    break;
                                }
                                continue;
                            }
                        }
                    }
                    self.presence_liveness(&agent, &peer);
                }
            }
            // `subscribe` needs the outbox + conn ownership for replay/live;
            // it enqueues replay itself and returns the control payload.
            // A `None` payload means the connection died mid-replay (writer
            // closed): break to cleanup without a second response.
            if op == "subscribe" && auth.is_some() {
                let (agent, token, policy) = auth.as_ref().unwrap();
                let agent = agent.clone();
                let token = token.clone();
                let policy = policy.clone();
                match self.op_subscribe(&agent, &token, &policy, &fr, conn_id, &outbox) {
                    Some(resp) => {
                        let frame = with_req_id(&req_id, &resp);
                        if outbox.push_control(frame, &self.drops).is_err() {
                            break;
                        }
                    }
                    None => break,
                }
                continue;
            }
            let resp = match op {
                "hello" => {
                    let token = fr.get("token").and_then(|t| t.as_str()).unwrap_or("");
                    let claimed = fr.get("agent").and_then(|a| a.as_str()).unwrap_or("");
                    let now = self.clock_now();
                    let authc = {
                        let store = self.tokens.lock().unwrap();
                        store.authenticate(token, claimed, now).cloned()
                    };
                    match authc {
                        Ok(policy) => {
                            // Identity boundary: prior subs + queued live
                            // never cross into the new identity (even on
                            // same-creds re-hello, clearing is safe: normal
                            // clients hello once per connection).
                            self.subs.lock().unwrap().remove_conn(conn_id);
                            outbox.purge_live_with_accounting(&self.drops);
                            {
                                let mut subs = self.subs.lock().unwrap();
                                subs.set_conn_auth(conn_id, token, &policy);
                            }
                            auth = Some((claimed.to_string(), token.to_string(), policy.clone()));
                            self.presence_hello(claimed, &peer);
                            json!({"ok": true, "agent": claimed})
                        }
                        Err(e) => {
                            if self.open_mode && !claimed.is_empty() {
                                let open = open_policy(claimed);
                                self.subs.lock().unwrap().remove_conn(conn_id);
                                outbox.purge_live_with_accounting(&self.drops);
                                {
                                    let mut subs = self.subs.lock().unwrap();
                                    subs.set_conn_auth(conn_id, token, &open);
                                }
                                auth = Some((claimed.to_string(), token.to_string(), open));
                                self.presence_hello(claimed, &peer);
                                json!({"ok": true, "agent": claimed})
                            } else {
                                // Legacy hello strings, never echoing the token.
                                // The clock is always finite here (system time
                                // or a finite test pin), so NonFiniteTime
                                // maps to the generic refusal (unreachable).
                                let msg = match e {
                                    crate::acl::AclError::TokenExpired => "token expired",
                                    crate::acl::AclError::AgentMismatch => "agent/token mismatch",
                                    _ => "auth failed",
                                };
                                json!({"error": msg})
                            }
                        }
                    }
                }
                "ping" => {
                    let now = self.clock_now();
                    if !now.is_finite() {
                        json!({"error": "non-finite time"})
                    } else if self.open_mode {
                        json!({"ok": true, "server_ts": now, "authed": auth.is_some()})
                    } else if let Some((agent, token, _)) = auth.clone() {
                        match self.revalidate_token(&agent, &token, now) {
                            Ok(fresh) => {
                                {
                                    let mut subs = self.subs.lock().unwrap();
                                    subs.set_conn_auth(conn_id, &token, &fresh);
                                    subs.prune_conn_for_policy(
                                        conn_id,
                                        &fresh,
                                        &outbox,
                                        &self.drops,
                                    );
                                }
                                auth = Some((agent, token, fresh));
                                json!({"ok": true, "server_ts": now, "authed": true})
                            }
                            Err(_) => {
                                self.subs.lock().unwrap().remove_conn(conn_id);
                                outbox.purge_live_with_accounting(&self.drops);
                                auth = None;
                                json!({"ok": true, "server_ts": now, "authed": false})
                            }
                        }
                    } else {
                        json!({"ok": true, "server_ts": now, "authed": false})
                    }
                }
                _ if auth.is_none() => json!({"error": "auth required (send hello first)"}),
                "post" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    self.op_post(agent, policy, &fr)
                }
                "fetch" => self.op_fetch(&auth.as_ref().unwrap().2, &fr),
                "subscribe" => {
                    // Unreachable: authed `subscribe` handled above with
                    // outbox; this arm is auth-gated denial only. Kept for
                    // exhaustiveness (auth.is_none() hits the guard above).
                    json!({"error": "auth required (send hello first)"})
                }
                "unsubscribe" => self.op_unsubscribe(conn_id, &fr),
                "subs" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    self.op_subs(agent, policy)
                }
                "claim_acquire" => self.op_acquire(auth.as_ref().unwrap().0.as_str(), &fr),
                "claim_renew" => self.op_renew(auth.as_ref().unwrap().0.as_str(), &fr),
                "claim_release" => self.op_release(auth.as_ref().unwrap().0.as_str(), &fr),
                "claim_status" => self.op_status(&fr),
                "claim_list" => self.op_list(),
                "kv_put" => self.op_kv_put(&auth.as_ref().unwrap().2, &fr),
                "kv_get" => self.op_kv_get(&auth.as_ref().unwrap().2, &fr),
                "kv_list" => self.op_kv_list(&auth.as_ref().unwrap().2, &fr),
                "kv_del" => self.op_kv_del(&auth.as_ref().unwrap().2, &fr),
                "heartbeat" => {
                    let agent = auth.as_ref().unwrap().0.clone();
                    self.op_heartbeat(&agent, &peer, &fr)
                }
                "agents" => self.op_agents(),
                "topics" => self.op_topics(&auth.as_ref().unwrap().2),
                "limits" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    self.op_limits(agent, policy)
                }
                "stats" => self.op_stats(),
                "token_issue" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    let agent = agent.clone();
                    let policy = policy.clone();
                    self.op_token_issue(&agent, &policy, &fr, &line)
                }
                "token_revoke" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    let agent = agent.clone();
                    let policy = policy.clone();
                    self.op_token_revoke(&agent, &policy, &fr)
                }
                "token_claim" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    let agent = agent.clone();
                    let policy = policy.clone();
                    self.op_token_claim(&agent, &policy, &fr)
                }
                "art_put" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    self.op_art_put(agent, policy, &fr)
                }
                "art_get" => self.op_art_get(&fr),
                "art_init" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    let resp = self.op_art_init(agent, policy, &fr);
                    if resp.get("ok") == Some(&json!(true)) {
                        if let Some(uid) = resp.get("upload_id").and_then(|v| v.as_str()) {
                            my_uploads.insert(uid.to_string());
                        }
                    }
                    resp
                }
                "art_chunk" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    self.op_art_chunk(agent, policy, &fr)
                }
                "art_commit" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    let resp = self.op_art_commit(agent, policy, &fr);
                    // Clean commits pop (ownership ends); commits that
                    // report `ok` plus `staging_cleanup_error` retain
                    // ownership so this connection's disconnect reaches
                    // its `CommittedCleanupPending` arm for one bounded
                    // unlink attempt (explicit `art_abort` retries too).
                    let clean = resp.get("ok") == Some(&json!(true))
                        && resp.get("staging_cleanup_error").is_none();
                    if clean {
                        if let Some(uid) = fr.get("upload_id").and_then(|v| v.as_str()) {
                            my_uploads.remove(uid);
                        }
                    }
                    resp
                }
                "art_abort" => {
                    let (agent, _, policy) = auth.as_ref().unwrap();
                    let resp = self.op_art_abort(agent, policy, &fr);
                    if resp.get("ok") == Some(&json!(true)) {
                        if let Some(uid) = fr.get("upload_id").and_then(|v| v.as_str()) {
                            my_uploads.remove(uid);
                        }
                    }
                    resp
                }
                "art_range" => self.op_art_range(&fr),
                "art_stat" => self.op_art_stat(&fr),
                _ => json!({"error": format!("unknown op: {op}")}),
            };
            let frame = with_req_id(&req_id, &resp);
            if outbox.push_control(frame, &self.drops).is_err() {
                break;
            }
        }
        // Disconnect cleanup (mirrors Python `finally: for sid in my_subs`
        // plus `for uid in my_uploads`, `broker.py:1531-1539`): release
        // owned subscriptions first (so no new live enqueues), abort
        // owned pending uploads (unlink staging under each per-upload
        // lock before exposing terminal, then pop, which also releases
        // the staging reservation), then close the outbox (drain for
        // protocol errors, discard for EOF/writer death) and join the
        // writer (no leaks). Unlink-before-terminal attempts
        // Python `pop+unlink` atomicity, but `remove_file` can fail under
        // ordinary IO errors: on failure the upload is retained (`Active`
        // or `CommittedCleanupPending`) for explicit `art_abort` retry and
        // counted in `stats.staging_cleanup_failed`, never silently
        // presented as complete. A commit reporting `ok` plus
        // `staging_cleanup_error` retains ownership (see `art_commit`
        // dispatch), so same-connection disconnect reaches the
        // `CommittedCleanupPending` arm for one bounded unlink attempt
        // (success pops + releases, failure retains + counts). For
        // owners, `unknown upload` therefore implies
        // unlinked-or-never-existed only when cleanup succeeded;
        // non-owners always miss as `unknown` to hide existence (staging
        // may still exist, owned by someone else). No global lock is held
        // across the unlink (per-upload lock only, allowed); retries are
        // explicit client `art_abort` or this single disconnect attempt
        // (bounded, no background workers).
        self.subs.lock().unwrap().remove_conn(conn_id);
        for uid in my_uploads {
            if let Some(handle) = self.artifacts.lookup_upload(&uid) {
                let should_pop = {
                    let mut up = handle.lock().unwrap();
                    match up.state {
                        crate::artifacts::UploadState::Active => {
                            let path = up.path.clone();
                            match self.artifacts.unlink_staging_owned(&path) {
                                Ok(()) => {
                                    up.state = crate::artifacts::UploadState::Aborted;
                                    true
                                }
                                Err(_) => false,
                            }
                        }
                        crate::artifacts::UploadState::CommittedCleanupPending => {
                            let path = up.path.clone();
                            match self.artifacts.unlink_staging_owned(&path) {
                                Ok(()) => {
                                    up.state = crate::artifacts::UploadState::Committed;
                                    true
                                }
                                Err(_) => false,
                            }
                        }
                        crate::artifacts::UploadState::Committed
                        | crate::artifacts::UploadState::Aborted => continue,
                    }
                };
                if should_pop {
                    self.artifacts.pop_upload(&uid);
                }
            }
        }
        if drain_close {
            outbox.close_after_drain();
        } else {
            outbox.close();
        }
        let _ = writer_join.join();
    }

    fn op_post(&self, agent: &str, policy: &Policy, fr: &Value) -> Value {
        let topic = fr.get("topic").and_then(|t| t.as_str()).unwrap_or("");
        if !policy.can_publish(topic) {
            return json!({"error": format!("publish denied: {topic}")});
        }
        if let Some(p) = self.poisoned_error() {
            return json!({"error": p});
        }
        let now = self.clock_now();
        if !now.is_finite() {
            return json!({"error": "non-finite time"});
        }
        let ttl_ms = match fr.get("ttl_ms") {
            None => None,
            Some(v) => match v.as_f64() {
                Some(t) => Some(t),
                None => return json!({"error": "ttl_ms must be a number"}),
            },
        };
        let payload = fr.get("payload").cloned().unwrap_or(Value::Null);
        let corr_id = fr.get("corr_id").cloned();
        let reply_to = fr.get("reply_to").cloned();
        let explicit = fr
            .get("msg_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let is_explicit = !explicit.is_empty();
        // Serialize dedup lookup, reservation, durable append, and commit
        // under one lock hold: concurrent duplicates serialize (first
        // commits, rest see it), sequence order == WAL order, and a WAL
        // failure rolls back the reservation instead of leaving a visible
        // but undurable message. The reservation never evicts, so a failure
        // at a full topic cannot lose prior retained history. Failed
        // appends leave no trace, so retries stay safe (never poisoned).
        let mut state = self.state.lock().unwrap();
        if is_explicit {
            enum Outcome {
                None,
                Retry(u64),
                ConflictSender,
                ConflictPayload,
            }
            let outcome = match state
                .topics
                .get(topic)
                .and_then(|t| t.find_live_by_id(&explicit, now))
            {
                None => Outcome::None,
                Some(prev) => {
                    if prev.sender != agent {
                        Outcome::ConflictSender
                    } else if prev.payload != payload
                        || norm_corr(&prev.corr_id) != norm_corr(&corr_id)
                        || norm_corr(&prev.reply_to) != norm_corr(&reply_to)
                    {
                        Outcome::ConflictPayload
                    } else {
                        Outcome::Retry(prev.seq)
                    }
                }
            };
            match outcome {
                Outcome::Retry(seq) => {
                    return json!({"ok": true, "id": explicit, "seq": seq, "dup": true});
                }
                Outcome::ConflictSender => {
                    return json!({"error": "msg_id conflict: id already used by different sender"});
                }
                Outcome::ConflictPayload => {
                    return json!({"error": "msg_id conflict: id reused with different payload; use a fresh id"});
                }
                Outcome::None => {}
            }
        }
        // Post rate gate (legacy `rate_rule_for`/`rate_take`, narrowed to
        // post-only): admin tokens (`agent == "*"`) bypass (still need
        // publish grants, checked above, no ACL broadening); otherwise
        // first-match topic rule else global via the validated policy.
        // Dup/conflict retries returned above without consuming tokens
        // (divergence from legacy rate-before-dedup, justified: retries
        // create no seq/WAL/posts/delivery, so they must not spend
        // budget; consistent with the retained-window no-mutation
        // guarantee). Denied ACL returned above without consuming
        // (preserved ACL-first). WAL failures below consume (rate before
        // WAL, preserved, shedding load before durable work).
        if policy.agent() != Some("*") {
            if let Some((rule_key, per_s)) = policy.rate_config().select(topic) {
                let (allowed, retry_ms) = self
                    .rate_limiter
                    .lock()
                    .unwrap()
                    .check(agent, rule_key, per_s, now);
                if !allowed {
                    self.rate_limited.fetch_add(1, Ordering::SeqCst);
                    return json!({
                        "error": "rate exceeded",
                        "retry_after_ms": round1_py(retry_ms),
                    });
                }
            }
        }
        let msg_id = if is_explicit {
            explicit.clone()
        } else {
            nanoid()
        };
        let mut msg = Msg {
            seq: 0,
            id: msg_id.clone(),
            sender: agent.to_string(),
            ts: now,
            exp: ttl_ms.map(|t| now + t / 1000.0),
            payload,
            corr_id,
            reply_to,
        };
        let seq = state.topic(topic).reserve_seq();
        msg.seq = seq;
        let rec = json!({"t": "post", "topic": topic, "msg": msg});
        match self.append_value_robust(&rec) {
            Ok(()) => {
                let stored = state.topic(topic).commit_reserved(msg, seq);
                self.posts.fetch_add(1, Ordering::SeqCst);
                // Durable-publication: live fan-out only after the WAL
                // append+fsync succeeds (retained retry returns early with
                // `dup` above, so no duplicate fan-out). Holds state ->
                // subs order across commit+collect+enqueue so a concurrent
                // subscribe snapshots either before (replay excludes, live
                // buffers) or after (replay includes) without gaps/dups,
                // and unsubscribe isolation is by op order. Enqueue is
                // non-blocking with drop accounting; slow subscribers never
                // block this lock beyond bounded queue ops.
                let msg_json = serde_json::to_value(&stored).unwrap_or(Value::Null);
                {
                    let mut subs = self.subs.lock().unwrap();
                    subs.deliver_live_with_clock(
                        topic,
                        now,
                        |sid| json!({"event": "msg", "sub_id": sid, "topic": topic, "msg": msg_json.clone()}),
                        &self.deliveries,
                        &self.drops,
                    );
                }
                json!({"ok": true, "id": msg_id, "seq": stored.seq})
            }
            Err(e) => {
                state.topic(topic).rollback_reserved(seq);
                json!({"error": e})
            }
        }
    }

    fn op_fetch(&self, policy: &Policy, fr: &Value) -> Value {
        let topic = fr.get("topic").and_then(|t| t.as_str()).unwrap_or("");
        if !policy.can_fetch(topic) {
            return json!({"error": format!("fetch denied: {topic}")});
        }
        let from_seq = match fr.get("from_seq") {
            None => 0,
            Some(v) => match v.as_u64() {
                Some(n) => n,
                None => return json!({"error": "from_seq must be a non-negative integer"}),
            },
        };
        let limit = match fr.get("limit") {
            None => 500,
            Some(v) => match v.as_u64() {
                Some(n) => n as usize,
                None => return json!({"error": "limit must be an integer"}),
            },
        };
        let until_seq = match fr.get("until_seq") {
            None | Some(Value::Null) => None,
            Some(v) => match v.as_u64() {
                Some(n) => Some(n),
                None => return json!({"error": "until_seq must be a non-negative integer"}),
            },
        };
        let state = self.state.lock().unwrap();
        let t = state.topics.get(topic);
        let empty = crate::history::Topic::default();
        let page = history_page(
            topic,
            t.unwrap_or(&empty),
            from_seq,
            limit,
            until_seq,
            self.clock_now(),
        );
        match page {
            Ok(p) => {
                json!({"ok": true, "topic": p.topic, "messages": p.messages, "cursor": p.cursor})
            }
            Err(e) => json!({"error": e.to_string()}),
        }
    }

    /// Authenticated live subscription (legacy `subscribe`,
    /// `broker.py:925-973`). Returns `Some(control)` with the
    /// `req_id`-bearing payload (`sub_id`/`replayed`/`cursor`), or `None`
    /// when the connection died mid-replay (caller breaks to cleanup).
    ///
    /// Validates `pattern` via conservative [`Policy::can_subscribe`]
    /// (empty denied) and `from_seq`/`tail` strictly as non-negative
    /// integers (missing means 0; floats/bools/strings/null are errors,
    /// unlike Python's truncating `int(... or 0)`). Registers as pending
    /// with a per-topic snapshot under state -> subs locks (no gaps/dups
    /// at the catch-up boundary: replay includes only `<= snapshot`,
    /// live committed after the snapshot buffers in bounded pending),
    /// replays sorted matching topics with expiry filtering and the 5000
    /// cap (reliable, never dropped, blocking only this reader), then
    /// activates and drains pending in order before the control reply.
    /// Replay frames precede the reply (matching Python order); the
    /// client buffers early live until the reply (see `StreamingConn`).
    /// Exact patterns (no `*?[` chars) also report the catch-up cursor
    /// (`topic_seq`/`oldest_seq`/`retained`/`truncated`) for
    /// `busclient.catchup_gap`. `oldest_seq`/`retained` are live-only
    /// (expired excluded, matching native `topics`); Python reports
    /// total retained.
    fn op_subscribe(
        &self,
        agent: &str,
        token: &str,
        policy: &Policy,
        fr: &Value,
        conn_id: u64,
        outbox: &std::sync::Arc<ConnOutbox>,
    ) -> Option<Value> {
        let now = self.clock_now();
        if !now.is_finite() {
            return Some(json!({"error": "non-finite time"}));
        }
        let pattern = fr.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
        if pattern.is_empty() || !policy.can_subscribe(pattern) {
            return Some(json!({"error": format!("subscribe denied: {pattern}")}));
        }
        let from_seq = match fr.get("from_seq") {
            None => 0u64,
            Some(v) => match v.as_u64() {
                Some(n) => n,
                None => return Some(json!({"error": "from_seq must be a non-negative integer"})),
            },
        };
        let tail = match fr.get("tail") {
            None => 0u64,
            Some(v) => match v.as_u64() {
                Some(n) => n,
                None => return Some(json!({"error": "tail must be a non-negative integer"})),
            },
        };
        let tail = tail as usize;
        let matcher = Matcher::new(pattern);
        // Register pending with snapshot under both locks (state -> subs).
        let (sub_id, snapshot, cursor_info) = {
            let state = self.state.lock().unwrap();
            let mut subs = self.subs.lock().unwrap();
            // Unique sub_id (retry on the ~2^-48 collision).
            let mut sub_id = crate::subs::gen_sub_id();
            while subs.contains(&sub_id) {
                sub_id = crate::subs::gen_sub_id();
            }
            // Snapshot heads for matching topics (sorted for determinism).
            let mut names: Vec<&String> = state.topics.keys().collect();
            names.sort();
            let mut snapshot = std::collections::HashMap::new();
            for tname in &names {
                if matcher.matches(tname) {
                    snapshot.insert((*tname).clone(), state.topics[*tname].seq);
                }
            }
            // Exact-topic cursor from the snapshot (not live heads, so gap
            // detection matches exactly what replay covers). Live-only:
            // expired payloads (`now > exp`) are excluded from
            // `oldest_seq`/`retained`, matching native `topics` (request-time
            // filter plus idle maintenance worker) so gap detection sees
            // expiry loss as unavailable rather than hiding it in `retained`.
            // Python reports total `len(msgs)`; native corrects to live-only
            // (see `docs/NATIVE_SUBSCRIPTIONS.md`).
            let cursor_info = if !pattern.chars().any(|c| c == '*' || c == '?' || c == '[') {
                match state.topics.get(pattern) {
                    None => Some((0u64, 1u64, 0usize)),
                    Some(t) if t.msgs.is_empty() => Some((t.seq, t.seq + 1, 0)),
                    Some(t) => {
                        let mut oldest: Option<u64> = None;
                        let mut retained: usize = 0;
                        for m in &t.msgs {
                            if m.exp.is_some_and(|e| now > e) {
                                continue;
                            }
                            if oldest.is_none() {
                                oldest = Some(m.seq);
                            }
                            retained += 1;
                        }
                        let oldest = oldest.unwrap_or(t.seq + 1);
                        Some((t.seq, oldest, retained))
                    }
                }
            } else {
                None
            };
            let counters = std::sync::Arc::new(crate::subs::SubCounters::new());
            let sub = Subscription {
                sub_id: sub_id.clone(),
                pattern: pattern.to_string(),
                matcher: matcher.clone(),
                agent: agent.to_string(),
                conn_id,
                outbox: std::sync::Arc::clone(outbox),
                created: now,
                counters,
                state: SubState::Pending(PendingState {
                    snapshot: snapshot.clone(),
                    now,
                    from_seq,
                    tail,
                    pending: std::collections::VecDeque::new(),
                }),
            };
            subs.register_pending(sub);
            subs.set_conn_auth(conn_id, token, policy);
            (sub_id, snapshot, cursor_info)
        };
        // Collect replay under a short state lock (no subs lock held, so
        // publishers proceed; live committed after the snapshot buffers in
        // pending, never duplicates replay which filters `<= snapshot`).
        let replay: Vec<(String, Value)> = {
            let state = self.state.lock().unwrap();
            let mut names: Vec<String> = snapshot.keys().cloned().collect();
            names.sort();
            let mut out = Vec::new();
            for tname in names {
                let Some(t) = state.topics.get(&tname) else {
                    continue;
                };
                let head = snapshot.get(&tname).copied().unwrap_or(0);
                // Snapshot slice: `<= head`, live at `now`, then tail/from.
                let mut msgs: Vec<&Msg> = t
                    .msgs
                    .iter()
                    .filter(|m| m.seq <= head && m.exp.is_none_or(|e| now <= e))
                    .collect();
                if tail > 0 && msgs.len() > tail {
                    msgs = msgs[msgs.len() - tail..].to_vec();
                }
                for m in msgs {
                    if m.seq > from_seq {
                        let msg_json = serde_json::to_value(m).unwrap_or(Value::Null);
                        out.push((
                            tname.clone(),
                            json!({"event": "msg", "sub_id": sub_id, "topic": tname, "msg": msg_json}),
                        ));
                        if out.len() >= SUBS_REPLAY_CAP {
                            break;
                        }
                    }
                }
                if out.len() >= SUBS_REPLAY_CAP {
                    break;
                }
            }
            out
        };
        // Enqueue replay reliably (never dropped for room, never evicts;
        // waits for room when full, blocking only this reader, never
        // publishers). Retains `sub_id` so auth purges + the writer check
        // treat replay as subscription data.
        for (_, frame) in &replay {
            if outbox.push_replay(&sub_id, frame.clone()).is_err() {
                // Connection died mid-replay: remove the pending sub and
                // signal the caller to break (no control reply).
                let mut subs = self.subs.lock().unwrap();
                subs.unsubscribe(conn_id, &sub_id);
                return None;
            }
        }
        let replayed = replay.len() as u64;
        self.replays.fetch_add(replayed, Ordering::SeqCst);
        // Activate + drain pending in order under the subs lock (registry
        // -> queue order, non-blocking live policy, bounded). New live
        // arriving during the drain waits on the registry lock, then
        // queues after pending (ordered, no gaps).
        {
            let mut subs = self.subs.lock().unwrap();
            let Some(sub) = subs.get_mut(&sub_id) else {
                // Removed during replay: disconnect (outbox closed) breaks
                // to cleanup; revocation sweep (outbox open) returns a
                // receipt so the client can re-hello instead of hanging.
                if outbox.is_closed() {
                    return None;
                }
                return Some(json!({"error": "auth failed"}));
            };
            // Only the owning connection's reader activates its own pending
            // sub (single-threaded per connection, so no race, but keep the
            // ownership guard local).
            if sub.conn_id != conn_id {
                return None;
            }
            let pending: Vec<Value> = match &mut sub.state {
                SubState::Pending(p) => p.pending.drain(..).collect(),
                SubState::Active => Vec::new(),
            };
            sub.state = SubState::Active;
            // Drain with live policy (droppable, evicting oldest live only).
            // Holds the registry lock across the drain so later live queues
            // after pending (ordered). Bounded + non-blocking: never waits.
            for frame in pending {
                sub.outbox.try_push_live(
                    &sub_id,
                    &sub.counters,
                    frame,
                    &self.deliveries,
                    &self.drops,
                );
            }
        }
        let mut resp = json!({"ok": true, "sub_id": sub_id, "replayed": replayed});
        if let Some((topic_seq, oldest_seq, retained)) = cursor_info {
            resp["cursor"] = json!({
                "topic": pattern,
                "topic_seq": topic_seq,
                "oldest_seq": oldest_seq,
                "retained": retained,
                "truncated": replayed >= SUBS_REPLAY_CAP as u64,
            });
        }
        Some(resp)
    }

    /// Per-connection isolated unsubscribe (legacy `unsubscribe`,
    /// `broker.py:1008-1013`): removes only when owned by `conn_id`,
    /// always replies ok (idempotent, no error for unknown/foreign ids).
    fn op_unsubscribe(&self, conn_id: u64, fr: &Value) -> Value {
        let sub_id = fr.get("sub_id").and_then(|v| v.as_str()).unwrap_or("");
        self.subs.lock().unwrap().unsubscribe(conn_id, sub_id);
        json!({"ok": true})
    }

    /// Authenticated subscription listing (legacy `subs`,
    /// `broker.py:976-991`): admin (`Policy::agent() == "*"`) sees all,
    /// others see only their claimed agent's subs. Rows carry `sub_id`/
    /// `pattern`/`agent`/`age_s` (half-even 1-decimal)/`delivered`/
    /// `dropped`/`queued` (shared per-connection outbox depth, matching
    /// Python `qsize()`). Fails closed on non-finite clocks.
    fn op_subs(&self, agent: &str, policy: &Policy) -> Value {
        let now = self.clock_now();
        if !now.is_finite() {
            return json!({"error": "non-finite time"});
        }
        let is_admin = policy.agent() == Some("*");
        let subs = self.subs.lock().unwrap();
        // Borrow ends before `round1_py` per row (pure, no locks).
        let mut rows = Vec::new();
        // Collect (sub_id, pattern, agent, created, delivered, dropped,
        // queued) for visible subs, then sort by sub_id for determinism
        // (Python iterates dict insertion order; sorted is stable and
        // documented in `docs/NATIVE_SUBSCRIPTIONS.md`).
        let mut vis = subs.snapshot_visible(is_admin, agent);
        vis.sort_by(|a, b| a.0.cmp(&b.0));
        for (sub_id, pattern, owner, created, delivered, dropped, queued) in vis {
            let delta = now - created;
            if !delta.is_finite() {
                return json!({"error": "non-finite time"});
            }
            rows.push(json!({
                "sub_id": sub_id,
                "pattern": pattern,
                "agent": owner,
                "age_s": round1_py(delta),
                "delivered": delivered,
                "dropped": dropped,
                "queued": queued,
            }));
        }
        json!({"ok": true, "subs": rows})
    }

    fn wal_sink(&self) -> WalSink {
        WalSink {
            server: self.clone(),
        }
    }

    fn op_acquire(&self, agent: &str, fr: &Value) -> Value {
        if let Some(p) = self.poisoned_error() {
            return json!({"error": p});
        }
        let resource = fr.get("resource").and_then(|v| v.as_str()).unwrap_or("");
        let ttl_ms = fr.get("ttl_ms").and_then(|v| v.as_u64()).unwrap_or(0);
        let idem = fr.get("idempotency_key").and_then(|v| v.as_str());
        let mut sink = self.wal_sink();
        match self.state.lock().unwrap().claims.acquire(
            &mut sink,
            agent,
            resource,
            ttl_ms,
            idem,
            self.clock_now(),
        ) {
            Ok(l) => {
                json!({"ok": true, "owner": l.owner, "resource": resource, "token": l.token, "fencing": l.fencing, "acquired_at": l.acquired_at, "expires_at": l.expires_at})
            }
            Err(e) => claim_err(e),
        }
    }

    fn op_renew(&self, agent: &str, fr: &Value) -> Value {
        if let Some(p) = self.poisoned_error() {
            return json!({"error": p});
        }
        let resource = fr.get("resource").and_then(|v| v.as_str()).unwrap_or("");
        let token = fr.get("token").and_then(|v| v.as_str()).unwrap_or("");
        let ttl_ms = fr.get("ttl_ms").and_then(|v| v.as_u64()).unwrap_or(0);
        let mut sink = self.wal_sink();
        match self.state.lock().unwrap().claims.renew(
            &mut sink,
            agent,
            resource,
            token,
            ttl_ms,
            self.clock_now(),
        ) {
            Ok(l) => {
                json!({"ok": true, "owner": l.owner, "resource": resource, "token": l.token, "fencing": l.fencing, "expires_at": l.expires_at})
            }
            Err(e) => claim_err(e),
        }
    }

    fn op_release(&self, agent: &str, fr: &Value) -> Value {
        if let Some(p) = self.poisoned_error() {
            return json!({"error": p});
        }
        let resource = fr.get("resource").and_then(|v| v.as_str()).unwrap_or("");
        let token = fr.get("token").and_then(|v| v.as_str()).unwrap_or("");
        let mut sink = self.wal_sink();
        match self
            .state
            .lock()
            .unwrap()
            .claims
            .release(&mut sink, agent, resource, token)
        {
            Ok(released) => json!({"ok": true, "released": released, "resource": resource}),
            Err(e) => claim_err(e),
        }
    }

    fn op_status(&self, fr: &Value) -> Value {
        let resource = fr.get("resource").and_then(|v| v.as_str()).unwrap_or("");
        match self
            .state
            .lock()
            .unwrap()
            .claims
            .status(resource, self.clock_now())
        {
            Some(l) => {
                json!({"ok": true, "owner": l.owner, "resource": resource, "token": l.token, "fencing": l.fencing, "expires_at": l.expires_at})
            }
            None => json!({"ok": true, "resource": resource, "live": false}),
        }
    }

    /// Authenticated live lease listing (legacy `claim_list`,
    /// `broker.py:1482-1493`, passive text reference). Any authed caller;
    /// no new ACL privilege, matching legacy (which checks no policy here).
    /// Samples one finite clock and lists with that instant, so all rows
    /// share state/clock consistency. Sorted by resource, live-only
    /// (`now < expires_at`), compact `{resource, holder, fencing,
    /// expires_at}` rows with NEVER a lease token. Read-only: no WAL, no
    /// purge, no mutation. Poison does not block reads (like `kv_get` /
    /// `claim_status`). Presence liveness refreshes via dispatch (like other
    /// claim ops) but never renews leases.
    fn op_list(&self) -> Value {
        let now = self.clock_now();
        if !now.is_finite() {
            return json!({"error": "non-finite time"});
        }
        let leases = self.state.lock().unwrap().claims.list_live(now);
        let out: Vec<Value> = leases
            .iter()
            .map(|l| {
                json!({
                    "resource": l.resource,
                    "holder": l.holder,
                    "fencing": l.fencing,
                    "expires_at": l.expires_at,
                })
            })
            .collect();
        json!({"ok": true, "leases": out})
    }

    fn op_kv_put(&self, policy: &Policy, fr: &Value) -> Value {
        let key = fr.get("key").and_then(|v| v.as_str()).unwrap_or("");
        if key.is_empty() {
            return json!({"error": "key required"});
        }
        if !policy.can_kv_write(key) {
            return json!({"error": format!("kv_put denied: {key}")});
        }
        if let Some(p) = self.poisoned_error() {
            return json!({"error": p});
        }
        // Fractional milliseconds preserved exactly (no rounding):
        // legacy stores `now + ttl/1000` for any truthy `ttl`.
        let ttl_ms = match fr.get("ttl_ms") {
            None | Some(Value::Null) => None,
            Some(v) => match v.as_f64() {
                Some(t) if t.is_finite() => Some(t),
                _ => return json!({"error": "ttl_ms must be a number"}),
            },
        };
        let value = fr.get("value").cloned().unwrap_or(Value::Null);
        let now = self.clock_now();
        let mut state = self.state.lock().unwrap();
        let pending = match state.kv.prepare_put_f64(key, value, ttl_ms, now) {
            Ok(p) => p,
            Err(KvError::EmptyKey) => return json!({"error": "key required"}),
            Err(KvError::NonFiniteTime) => return json!({"error": "non-finite time"}),
            Err(KvError::BadSnapshot(detail)) => {
                return json!({"error": format!("bad snapshot: {detail}")})
            }
        };
        let this = self.clone();
        match state
            .kv
            .commit_put(pending, |line| this.append_line_robust(line))
        {
            Ok(()) => json!({"ok": true, "key": key}),
            Err(e) => json!({"error": e}),
        }
    }

    fn op_kv_get(&self, policy: &Policy, fr: &Value) -> Value {
        let key = fr.get("key").and_then(|v| v.as_str()).unwrap_or("");
        if !policy.can_kv_read(key) {
            return json!({"error": format!("kv_get denied: {key}")});
        }
        let state = self.state.lock().unwrap();
        match state.kv.get(key, self.clock_now()) {
            Some(value) => json!({"ok": true, "found": true, "value": value}),
            None => json!({"ok": true, "found": false}),
        }
    }

    fn op_kv_list(&self, policy: &Policy, fr: &Value) -> Value {
        let prefix = fr.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
        if !policy.can_kv_list(prefix) {
            return json!({"error": format!("kv_list denied: {prefix}")});
        }
        let state = self.state.lock().unwrap();
        let keys = state
            .kv
            .list_filtered(prefix, self.clock_now(), |k| policy.kv_key_visible(k));
        json!({"ok": true, "keys": keys})
    }

    fn op_kv_del(&self, policy: &Policy, fr: &Value) -> Value {
        let key = fr.get("key").and_then(|v| v.as_str()).unwrap_or("");
        if key.is_empty() {
            return json!({"error": "key required"});
        }
        if !policy.can_kv_write(key) {
            return json!({"error": format!("kv_del denied: {key}")});
        }
        if let Some(p) = self.poisoned_error() {
            return json!({"error": p});
        }
        let mut state = self.state.lock().unwrap();
        let pending = match state.kv.prepare_delete(key) {
            Ok(p) => p,
            Err(KvError::EmptyKey) => return json!({"error": "key required"}),
            Err(KvError::NonFiniteTime) => return json!({"error": "non-finite time"}),
            Err(KvError::BadSnapshot(detail)) => {
                return json!({"error": format!("bad snapshot: {detail}")})
            }
        };
        let this = self.clone();
        match state
            .kv
            .commit_delete(pending, |line| this.append_line_robust(line))
        {
            Ok(found) => json!({"ok": true, "key": key, "found": found}),
            Err(e) => json!({"error": e}),
        }
    }

    /// Hello reconnect rule (memory-only, never WAL): absent agents get
    /// `"online"`, present agents preserve status; both refresh
    /// `last_seen`+`addr`. Skips on non-finite clocks (hello still ok).
    fn presence_hello(&self, agent: &str, peer: &str) {
        let now = self.clock_now();
        if !now.is_finite() {
            return;
        }
        let mut p = self.presence.lock().unwrap();
        p.prune(now);
        p.hello_touch(agent, now, peer);
    }

    /// Generic liveness for every authenticated op (even denied/unknown):
    /// prunes, then refreshes `last_seen`+`addr` preserving status.
    /// Skips on non-finite clocks (op still proceeds with its own rules).
    fn presence_liveness(&self, agent: &str, peer: &str) {
        let now = self.clock_now();
        if !now.is_finite() {
            return;
        }
        let mut p = self.presence.lock().unwrap();
        p.prune(now);
        p.touch(agent, None, now, peer);
    }

    fn op_heartbeat(&self, agent: &str, peer: &str, fr: &Value) -> Value {
        let now = self.clock_now();
        if !now.is_finite() {
            return json!({"error": "non-finite time"});
        }
        // Missing `status` defaults to `"online"`; explicit null preserves;
        // anything else coerces (bools `True`/`False`, numbers as text,
        // containers as compact JSON) and truncates to 200 chars.
        let status: Option<String> = match fr.get("status") {
            None => Some("online".to_string()),
            Some(Value::Null) => None,
            Some(v) => Some(coerce_status(v)),
        };
        let mut p = self.presence.lock().unwrap();
        p.prune(now);
        p.touch(agent, status.as_deref(), now, peer);
        json!({"ok": true})
    }

    fn op_agents(&self) -> Value {
        let now = self.clock_now();
        if !now.is_finite() {
            return json!({"error": "non-finite time"});
        }
        let mut p = self.presence.lock().unwrap();
        p.prune(now);
        match p.agents_snapshot(now) {
            Some(agents) => json!({"ok": true, "agents": agents}),
            None => json!({"error": "non-finite time"}),
        }
    }

    /// Authenticated topic listing (legacy `topics`, `broker.py:994-1006`).
    /// Sorted, filtered by `subscribe` cover (`Policy::topic_visible`),
    /// with high-water `seq`, live `retained`, and last live `last_ts`
    /// (null when no live message). Expiry is filtered at the request clock
    /// plus the idle maintenance worker releases payloads (see
    /// `docs/NATIVE_EXPIRY_MAINTENANCE.md`); see
    /// `docs/NATIVE_INTROSPECTION.md`.
    fn op_topics(&self, policy: &Policy) -> Value {
        let now = self.clock_now();
        if !now.is_finite() {
            return json!({"error": "non-finite time"});
        }
        let state = self.state.lock().unwrap();
        let mut names: Vec<&String> = state
            .topics
            .keys()
            .filter(|t| policy.topic_visible(t))
            .collect();
        names.sort();
        let mut mine = Vec::with_capacity(names.len());
        for tname in names {
            let t = &state.topics[tname];
            let mut retained: usize = 0;
            let mut last_ts: Value = Value::Null;
            for m in &t.msgs {
                if m.exp.is_some_and(|e| now > e) {
                    continue;
                }
                retained += 1;
                last_ts = json!(m.ts);
            }
            mine.push(json!({
                "topic": tname,
                "seq": t.seq,
                "retained": retained,
                "last_ts": last_ts,
            }));
        }
        json!({"ok": true, "topics": mine})
    }

    /// Authenticated per-token limits (legacy `limits`,
    /// `broker.py:1495-1501`). `art_used_bytes` is the live charged
    /// usage for `agent` (WAL-seeded, reservation-charged; see
    /// `docs/NATIVE_ARTIFACTS.md`); quota/rate fields echo the
    /// authenticated policy's preserved `extra` config (`null`/`{}`
    /// when absent, matching `info.get(...)` / `or {}`). Rate values
    /// are enforced on `post` via `crate::rate` (see
    /// `docs/NATIVE_RATE_LIMITS.md`); artifact quotas are enforced on
    /// `art_put`/`art_init`/`art_commit` in wire (ACL-only
    /// `enforce_artifact_quota` stays `Unsupported`, like
    /// `enforce_rate_limit`); `enforce_token_admin` stays
    /// `Unsupported` for ACL-only callers (live in wire).
    fn op_limits(&self, agent: &str, policy: &Policy) -> Value {
        let extra = policy.extra();
        let art_quota_bytes = extra.get("art_quota_bytes").cloned().unwrap_or(Value::Null);
        let rate_per_s = extra.get("rate_per_s").cloned().unwrap_or(Value::Null);
        let topic_rates = match extra.get("topic_rates") {
            None | Some(Value::Null) => json!({}),
            Some(v) if crate::rate::is_falsy(v) => json!({}),
            Some(v) => v.clone(),
        };
        json!({
            "ok": true,
            "art_used_bytes": self.artifacts.usage_of(agent),
            "art_quota_bytes": art_quota_bytes,
            "rate_per_s": rate_per_s,
            "topic_rates": topic_rates,
        })
    }

    /// Authenticated broker health (legacy `stats`, `broker.py:1517-1527`,
    /// narrowed to source-backed fields). `started`/`posts`/
    /// `deliveries`/`drops`/`replays`/`rate_limited`/`quota_denied`/
    /// `staging_cleanup_failed` come from the live server, `topics` from `BusState`, `agents`
    /// from pruned presence, `subs` from the live subscription table,
    /// `kv_keys` from live KV, `wal_bytes` from the WAL file (0 on
    /// stat failure), and `uptime_s` from half-even
    /// `round1_py(now-started)`; see `docs/NATIVE_INTROSPECTION.md`,
    /// `docs/NATIVE_SUBSCRIPTIONS.md`, `docs/NATIVE_RATE_LIMITS.md`,
    /// and `docs/NATIVE_ARTIFACTS.md`.
    fn op_stats(&self) -> Value {
        let now = self.clock_now();
        if !now.is_finite() {
            return json!({"error": "non-finite time"});
        }
        let started = self.started();
        if !started.is_finite() {
            return json!({"error": "non-finite time"});
        }
        let uptime = now - started;
        if !uptime.is_finite() {
            return json!({"error": "non-finite time"});
        }
        let (topics, kv_keys) = {
            let state = self.state.lock().unwrap();
            (state.topics.len(), state.kv.live_len(now))
        };
        let agents = {
            let mut p = self.presence.lock().unwrap();
            p.prune(now);
            p.len()
        };
        let subs = self.subs.lock().unwrap().len();
        let wal_bytes = std::fs::metadata(&self.wal_path)
            .map(|m| m.len())
            .unwrap_or(0);
        json!({
            "ok": true,
            "stats": {
                "started": started,
                "posts": self.posts.load(Ordering::SeqCst),
                "deliveries": self.deliveries.load(Ordering::SeqCst),
                "drops": self.drops.load(Ordering::SeqCst),
                "replays": self.replays.load(Ordering::SeqCst),
                "rate_limited": self.rate_limited.load(Ordering::SeqCst),
                "quota_denied": self.artifacts.quota_denied(),
                "staging_cleanup_failed": self.artifacts.staging_cleanup_failed(),
                "topics": topics,
                "subs": subs,
                "agents": agents,
                "kv_keys": kv_keys,
                "wal_bytes": wal_bytes,
                "uptime_s": round1_py(uptime),
            }
        })
    }

    /// Authenticated single-put (legacy `art_put`, `broker.py:1086-1116`):
    /// base64 decode, `ART_MAX` cap, optional sha-want check, reservation
    /// quota charge, durable staging+rename publish, WAL `art_own`
    /// append+fsync before ack, keep charge. Failures roll back the
    /// charge (never charge nonexistent) and never delete `final`
    /// (never lose existing); WAL failure leaves orphan bytes for the
    /// retry to dedup+charge. Refuses when WAL poisoned.
    fn op_art_put(&self, agent: &str, policy: &Policy, fr: &Value) -> Value {
        use crate::artifacts as art;
        if let Some(p) = self.poisoned_error() {
            return json!({"error": p});
        }
        let enc = match fr.get("data_b64") {
            None => "",
            Some(Value::String(s)) => s.as_str(),
            Some(_) => return json!({"error": "bad base64"}),
        };
        if enc.len() as u64 > art::max_b64_len(art::ART_MAX) {
            return json!({"error": "artifact too large (32MB cap)"});
        }
        let raw = match art::base64_decode(enc) {
            Ok(v) => v,
            Err(e) => return json!({"error": e}),
        };
        if raw.len() as u64 > art::ART_MAX {
            return json!({"error": "artifact too large (32MB cap)"});
        }
        let sha = art::sha256_hex(&raw);
        if let Some(v) = fr.get("sha") {
            if py_truthy(v) && v != &json!(sha) {
                return json!({"error": "sha mismatch"});
            }
        }
        let quota = art::parse_quota(policy.extra().get("art_quota_bytes"));
        let size = raw.len() as u64;
        if let Err(e) = self.artifacts.try_charge(agent, size, quota) {
            return json!({"error": e});
        }
        let (sha2, dedup) = match self.artifacts.put_bytes_durable(&raw) {
            Ok(v) => v,
            Err(e) => {
                self.artifacts.uncharge(agent, size);
                return json!({"error": e});
            }
        };
        debug_assert_eq!(sha, sha2);
        let rec = json!({"t": "art_own", "sha": sha, "agent": agent, "size": size});
        if let Err(e) = self.append_value_robust(&rec) {
            self.artifacts.uncharge(agent, size);
            return json!({"error": e});
        }
        json!({"ok": true, "sha": sha, "size": size, "dedup": dedup})
    }

    /// Authenticated full read (legacy `art_get`, `broker.py:1118-1128`):
    /// any authed agent reads any committed hex sha (no per-artifact
    /// ACL). Reads stay available when WAL poisoned. Large objects
    /// should use `art_range` streaming (the native `Client` caps
    /// replies at 8 MiB; the broker still serves full `art_get` for
    /// legacy parity).
    fn op_art_get(&self, fr: &Value) -> Value {
        use crate::artifacts as art;
        let sha = fr.get("sha").and_then(|v| v.as_str()).unwrap_or("");
        match self.artifacts.get_bytes(sha) {
            Ok(raw) => json!({
                "ok": true, "sha": sha, "size": raw.len() as u64,
                "data_b64": art::base64_encode(&raw),
            }),
            Err(e) => json!({"error": e}),
        }
    }

    /// Authenticated upload init (legacy `art_init`, `broker.py:1130-1155`):
    /// strict `1 <= size <= ART_MAX`, advisory quota pre-check (no
    /// charge until commit), optional sha-shape validation (fail fast),
    /// staging admission against `StagingLimits` (count/byte denials
    /// reserve nothing and bump no counter), then reservation plus
    /// private staging create (rolled back on IO failure). Allowed when
    /// WAL poisoned (no WAL yet; commit will refuse). Caller tracks
    /// `upload_id` for disconnect cleanup.
    fn op_art_init(&self, agent: &str, policy: &Policy, fr: &Value) -> Value {
        use crate::artifacts as art;
        let size = match fr.get("size").and_then(|v| v.as_u64()) {
            Some(n) if n >= 1 && n <= art::ART_MAX => n,
            _ => return json!({"error": format!("bad size (1..{})", art::ART_MAX)}),
        };
        let want: Option<String> = match fr.get("sha") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(Value::String(s)) if art::is_valid_sha(s) => Some(s.clone()),
            Some(v) if !py_truthy(v) => None,
            _ => return json!({"error": "sha mismatch"}),
        };
        let quota = art::parse_quota(policy.extra().get("art_quota_bytes"));
        if let Err(e) = self.artifacts.check_available(agent, size, quota) {
            return json!({"error": e});
        }
        match self.artifacts.init_upload(agent, size, want) {
            Ok(uid) => json!({"ok": true, "upload_id": uid, "size": size}),
            Err(e) => json!({"error": e}),
        }
    }

    /// Authenticated chunk append (legacy `art_chunk`,
    /// `broker.py:1157-1185`): owner-or-admin, strict `off == received`,
    /// base64 decode, `CHUNK_MAX` + `received+len <= size` bounds,
    /// append under the per-upload lock (no global locks across IO).
    /// Allowed when WAL poisoned (staging only). `Active` only;
    /// `CommittedCleanupPending` reports `already committed (staging
    /// cleanup pending...)` to owners (never `unknown upload`, which
    /// would falsely imply unlinked) and `unknown upload` to
    /// non-owners (hide existence); `Committed`/`Aborted` miss as
    /// `unknown upload` (already unlinked and popped imminently).
    fn op_art_chunk(&self, agent: &str, policy: &Policy, fr: &Value) -> Value {
        use crate::artifacts as art;
        let uid = fr.get("upload_id").and_then(|v| v.as_str()).unwrap_or("");
        let handle = match self.artifacts.lookup_upload(uid) {
            Some(h) => h,
            None => return json!({"error": "unknown upload"}),
        };
        let mut up = handle.lock().unwrap();
        if up.state == crate::artifacts::UploadState::CommittedCleanupPending {
            if !(up.agent == agent || policy.agent() == Some("*")) {
                return json!({"error": "unknown upload"});
            }
            return json!({"error": "already committed (staging cleanup pending; retry via art_abort)"});
        }
        if up.state != crate::artifacts::UploadState::Active {
            return json!({"error": "unknown upload"});
        }
        if !(up.agent == agent || policy.agent() == Some("*")) {
            return json!({"error": "unknown upload"});
        }
        let received = up.received;
        match fr.get("off").and_then(|v| v.as_u64()) {
            Some(o) if o == received => {}
            _ => return json!({"error": format!("bad off: want {received}")}),
        }
        let enc = match fr.get("data_b64") {
            None => "",
            Some(Value::String(s)) => s.as_str(),
            Some(_) => return json!({"error": "bad base64"}),
        };
        if enc.len() as u64 > art::max_b64_len(art::CHUNK_MAX) {
            return json!({"error": "chunk too large"});
        }
        let raw = match art::base64_decode(enc) {
            Ok(v) => v,
            Err(e) => return json!({"error": e}),
        };
        let len = raw.len() as u64;
        if len > art::CHUNK_MAX {
            return json!({"error": "chunk too large"});
        }
        match received.checked_add(len) {
            Some(total) if total <= up.size => {}
            _ => return json!({"error": "chunk too large"}),
        }
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.append(true);
            match opts.open(&up.path) {
                Ok(mut f) => {
                    if let Err(e) = f.write_all(&raw) {
                        return json!({"error": format!("stage write failed: {e}")});
                    }
                }
                Err(e) => return json!({"error": format!("stage write failed: {e}")}),
            }
        }
        up.received = received + len;
        json!({"ok": true, "received": up.received})
    }

    /// Authenticated upload commit (legacy `art_commit`,
    /// `broker.py:1187-1229`): owner-or-admin, `received == size`,
    /// streaming hash + file-size verification, expected-sha check,
    /// committer reservation charge (legacy charges the committer,
    /// not the initiator), hardlink publish (staging kept until WAL
    /// succeeds so retries work), WAL `art_own` before ack, then unlink
    /// staging under the per-upload lock before exposing terminal, then
    /// pop. Bytes/WAL failures keep `Active` (retryable) and roll back
    /// the charge; WAL success never uncharges or double-charges.
    /// Staging unlink after WAL success uses
    /// `ArtifactStore::unlink_staging_owned`: success pops and returns
    /// the committed receipt (`ok`, `sha`, `size`, `dedup`, unchanged);
    /// failure retains `CommittedCleanupPending` (no pop, no uncharge,
    /// no recommit, reservation held), counts
    /// `stats.staging_cleanup_failed`, and returns the same receipt plus
    /// `staging_cleanup_error` (observable, never silently complete).
    /// Cleanup retries via explicit `art_abort` or the owning
    /// connection's single disconnect attempt (ownership is retained on
    /// this receipt; bounded, no workers); late `art_commit`/`art_chunk`
    /// on pending report `already committed (staging cleanup pending...)`
    /// to owners (never `unknown upload`) and `unknown upload` to
    /// non-owners. Refuses when WAL poisoned.
    fn op_art_commit(&self, agent: &str, policy: &Policy, fr: &Value) -> Value {
        use crate::artifacts as art;
        if let Some(p) = self.poisoned_error() {
            return json!({"error": p});
        }
        let uid = fr.get("upload_id").and_then(|v| v.as_str()).unwrap_or("");
        let handle = match self.artifacts.lookup_upload(uid) {
            Some(h) => h,
            None => return json!({"error": "unknown upload"}),
        };
        let mut up = handle.lock().unwrap();
        if up.state == crate::artifacts::UploadState::CommittedCleanupPending {
            if !(up.agent == agent || policy.agent() == Some("*")) {
                return json!({"error": "unknown upload"});
            }
            return json!({"error": "already committed (staging cleanup pending; retry via art_abort)"});
        }
        if up.state != crate::artifacts::UploadState::Active {
            return json!({"error": "unknown upload"});
        }
        if !(up.agent == agent || policy.agent() == Some("*")) {
            return json!({"error": "unknown upload"});
        }
        if up.received != up.size {
            return json!({"error": format!("incomplete: {}/{}", up.received, up.size)});
        }
        let staging = up.path.clone();
        let size = up.size;
        let want = up.sha.clone();
        let (sha, hashed) = match art::ArtifactStore::hash_file(&staging, art::ART_MAX) {
            Ok(v) => v,
            Err(e) => return json!({"error": e}),
        };
        if hashed != size {
            return json!({"error": "commit failed: size changed under upload"});
        }
        if let Some(w) = &want {
            if w != &sha {
                return json!({"error": "sha mismatch"});
            }
        }
        let quota = art::parse_quota(policy.extra().get("art_quota_bytes"));
        if let Err(e) = self.artifacts.try_charge(agent, size, quota) {
            return json!({"error": e});
        }
        let dedup = match self.artifacts.publish_staged(&staging, &sha) {
            Ok(d) => d,
            Err(e) => {
                self.artifacts.uncharge(agent, size);
                return json!({"error": e});
            }
        };
        let rec = json!({"t": "art_own", "sha": sha, "agent": agent, "size": size});
        if let Err(e) = self.append_value_robust(&rec) {
            self.artifacts.uncharge(agent, size);
            return json!({"error": e});
        }
        // WAL is durable and the charge is kept from here on: never
        // uncharge or recommit/double-charge. Unlink staging (owned,
        // per-upload lock only, no global locks); success pops and returns
        // the committed receipt unchanged, failure retains
        // `CommittedCleanupPending` for explicit `art_abort` retry and
        // returns the same receipt plus `staging_cleanup_error`.
        let path = up.path.clone();
        match self.artifacts.unlink_staging_owned(&path) {
            Ok(()) => {
                up.state = crate::artifacts::UploadState::Committed;
                drop(up);
                self.artifacts.pop_upload(uid);
                json!({"ok": true, "sha": sha, "size": size, "dedup": dedup})
            }
            Err(e) => {
                up.state = crate::artifacts::UploadState::CommittedCleanupPending;
                drop(up);
                json!({
                    "ok": true, "sha": sha, "size": size, "dedup": dedup,
                    "staging_cleanup_error": e,
                })
            }
        }
    }

    /// Authenticated upload abort (legacy `art_abort`,
    /// `broker.py:1231-1245`): owner-or-admin, unlink staging under the
    /// per-upload lock before exposing terminal, then pop. Allowed when
    /// WAL poisoned (no WAL). `Active` aborts and pops on unlink success
    /// (`ok`); unlink failure retains `Active` for retry and returns
    /// `abort failed: staging cleanup failed...` (never silently `ok`,
    /// counted in `stats.staging_cleanup_failed`). Also retries
    /// `CommittedCleanupPending` commit orphans (owner-or-admin): success
    /// pops and returns `ok` (charge stays kept, no uncharge), failure
    /// retains pending and returns the same abort error. `Committed`/
    /// `Aborted` miss as `unknown upload` (already unlinked); non-owners
    /// always miss as `unknown` to hide existence (staging may still
    /// exist, owned by someone else). No global locks across IO; retries
    /// are explicit client `art_abort` calls or the owning connection's
    /// single disconnect attempt (bounded, no workers).
    fn op_art_abort(&self, agent: &str, policy: &Policy, fr: &Value) -> Value {
        let uid = fr.get("upload_id").and_then(|v| v.as_str()).unwrap_or("");
        let handle = match self.artifacts.lookup_upload(uid) {
            Some(h) => h,
            None => return json!({"error": "unknown upload"}),
        };
        {
            let mut up = handle.lock().unwrap();
            match up.state {
                crate::artifacts::UploadState::Active => {
                    if !(up.agent == agent || policy.agent() == Some("*")) {
                        return json!({"error": "unknown upload"});
                    }
                    let path = up.path.clone();
                    match self.artifacts.unlink_staging_owned(&path) {
                        Ok(()) => {
                            up.state = crate::artifacts::UploadState::Aborted;
                        }
                        Err(e) => {
                            return json!({"error": format!("abort failed: {e}")});
                        }
                    }
                }
                crate::artifacts::UploadState::CommittedCleanupPending => {
                    if !(up.agent == agent || policy.agent() == Some("*")) {
                        return json!({"error": "unknown upload"});
                    }
                    let path = up.path.clone();
                    match self.artifacts.unlink_staging_owned(&path) {
                        Ok(()) => {
                            up.state = crate::artifacts::UploadState::Committed;
                        }
                        Err(e) => {
                            return json!({"error": format!("abort failed: {e}")});
                        }
                    }
                }
                crate::artifacts::UploadState::Committed
                | crate::artifacts::UploadState::Aborted => {
                    return json!({"error": "unknown upload"});
                }
            }
        };
        self.artifacts.pop_upload(uid);
        json!({"ok": true})
    }

    /// Authenticated range read (legacy `art_range`,
    /// `broker.py:1247-1269`): any authed agent, strict `off`/`len`
    /// integers (missing defaults 0, like legacy `fr.get(...,0)`),
    /// `len <= CHUNK_MAX`, `off <= size`, clamped. Reads stay
    /// available when WAL poisoned.
    fn op_art_range(&self, fr: &Value) -> Value {
        use crate::artifacts as art;
        let sha = fr.get("sha").and_then(|v| v.as_str()).unwrap_or("");
        let off = match fr.get("off") {
            None => 0u64,
            Some(v) => match v.as_u64() {
                Some(n) => n,
                None => return json!({"error": "bad range"}),
            },
        };
        let len = match fr.get("len") {
            None => 0u64,
            Some(v) => match v.as_u64() {
                Some(n) => n,
                None => return json!({"error": "bad range"}),
            },
        };
        match self.artifacts.range(sha, off, len) {
            Ok((bytes, size)) => json!({
                "ok": true, "sha": sha, "off": off, "size": size,
                "data_b64": art::base64_encode(&bytes),
            }),
            Err(e) => json!({"error": e}),
        }
    }

    /// Authenticated stat (legacy `art_stat`, `broker.py:1271-1279`):
    /// any authed agent, size only. Reads stay available when WAL
    /// poisoned.
    fn op_art_stat(&self, fr: &Value) -> Value {
        let sha = fr.get("sha").and_then(|v| v.as_str()).unwrap_or("");
        match self.artifacts.stat(sha) {
            Ok(size) => json!({"ok": true, "sha": sha, "size": size}),
            Err(e) => json!({"error": e}),
        }
    }

    /// Re-check a hello token against the live store (prompt revocation).
    /// Presence + name always; expiry only when `now` finite (preserves
    /// clock-free ops like `limits` under non-finite pins). Errors reuse
    /// hello strings, never echo the token.
    fn revalidate_token(&self, agent: &str, token: &str, now: f64) -> Result<Policy, String> {
        let store = self.tokens.lock().unwrap();
        let policy = store.get(token).ok_or_else(|| "auth failed".to_string())?;
        if now.is_finite() && policy.is_expired(now) {
            return Err("token expired".to_string());
        }
        if !policy.name_allowed(agent) {
            return Err("agent/token mismatch".to_string());
        }
        Ok(policy.clone())
    }

    fn op_token_issue(&self, _agent: &str, policy: &Policy, fr: &Value, raw_line: &str) -> Value {
        if policy.agent() != Some("*") {
            return json!({"error": "admin required"});
        }
        if self.open_mode {
            return json!({"error": "unsupported in open mode"});
        }
        let path = match &self.tokens_path {
            Some(p) => p.clone(),
            None => return json!({"error": "token persistence not configured"}),
        };
        let now = self.clock_now();
        if !now.is_finite() {
            return json!({"error": "non-finite time"});
        }
        let agent_name = fr.get("agent").and_then(|v| v.as_str()).unwrap_or("");
        if !crate::tokens::is_valid_agent_name(agent_name) {
            return json!({"error": "bad agent name"});
        }
        let ttl_opt = match crate::tokens::parse_ttl_s(fr.get("ttl_s")) {
            Ok(v) => v,
            Err(e) => return json!({"error": e}),
        };
        let exp = match ttl_opt {
            None => None,
            Some(ttl) => {
                let e = now + ttl;
                if !e.is_finite() {
                    return json!({"error": "bad ttl_s: exp must be finite"});
                }
                Some(e)
            }
        };
        let entry = match crate::tokens::build_issue_entry(agent_name, exp, fr) {
            Ok(v) => v,
            Err(e) => return json!({"error": e}),
        };
        let new_policy = match Policy::from_json(&entry) {
            Ok(p) => p,
            Err(e) => return json!({"error": e.to_string()}),
        };
        // Preserve request-document first-match order (not sorted `Value`
        // order). `from_json` validated grants/exp/global and the topic-rules
        // shape order-independently; replace sorted rules with wire-ordered
        // rules so overlapping patterns keep caller declaration order through
        // validation, persistence, and reload. Fail closed on any inconsistency
        // (same `bad policy` wrapping, never echoing the request).
        let new_policy = match parse_issue_ordered_rates(raw_line) {
            Err(e) => return json!({"error": format!("bad policy: {e}")}),
            Ok(None) => new_policy,
            Ok(Some(pairs)) => {
                if pairs.is_empty() {
                    new_policy
                } else {
                    match new_policy.with_ordered_topic_rates(pairs) {
                        Ok(p) => p,
                        Err(e) => return json!({"error": format!("bad policy: {e}")}),
                    }
                }
            }
        };
        let mut store = self.tokens.lock().unwrap();
        if self.token_poison.lock().unwrap().is_some() {
            return json!({"error": "token store poisoned"});
        }
        let mut raw_guard = self.tokens_raw.lock().unwrap();
        if raw_guard.is_none() {
            match crate::tokens::load_raw_root(&path) {
                Ok(m) => *raw_guard = Some(m),
                Err(e) => return json!({"error": e}),
            }
        }
        let raw_map = raw_guard.as_mut().unwrap();
        if let Err(e) = check_raw_store_sync_for_insert(raw_map, &store) {
            return json!({"error": e});
        }
        let mut token = String::new();
        let mut found = false;
        for _ in 0..8 {
            let hex = match crate::tokens::secure_random_hex(crate::tokens::TOKEN_RANDOM_BYTES) {
                Ok(h) => h,
                Err(e) => return json!({"error": e}),
            };
            let candidate = crate::tokens::make_token(agent_name, &hex);
            if store.get(&candidate).is_none() && !raw_map.contains_key(&candidate) {
                token = candidate;
                found = true;
                break;
            }
        }
        if !found {
            return json!({"error": "token collision, retry"});
        }
        raw_map.insert(token.clone(), entry.clone());
        let root_value = Value::Object(raw_map.clone().into_iter().collect());
        if let Err(e) = TokenStore::from_root(&root_value) {
            raw_map.remove(&token);
            return json!({"error": e.to_string()});
        }
        let order_map = build_ordered_rates(raw_map, &store, Some((token.as_str(), &new_policy)));
        let text = match crate::tokens::render_tokens_root_ordered(raw_map, &order_map) {
            Ok(t) => t,
            Err(e) => {
                raw_map.remove(&token);
                return json!({"error": e});
            }
        };
        let failpoint = self.tokens_failpoint.load(Ordering::SeqCst);
        match crate::tokens::persist_tokens_text(&path, &text, failpoint) {
            Ok(()) => match TokenStore::from_json_str(&text) {
                Ok(new_store) => {
                    *store = new_store;
                    match exp {
                        Some(e) => {
                            json!({"ok": true, "token": token, "agent": agent_name, "exp": e})
                        }
                        None => {
                            json!({"ok": true, "token": token, "agent": agent_name, "exp": Value::Null})
                        }
                    }
                }
                Err(_) => {
                    *self.token_poison.lock().unwrap() = Some("reload failed".to_string());
                    raw_map.remove(&token);
                    json!({"error": "token store reload failed"})
                }
            },
            Err(e) => {
                if e.post_rename_uncertain {
                    if let Ok(new_store) = TokenStore::from_json_str(&text) {
                        *store = new_store;
                    } else {
                        raw_map.remove(&token);
                    }
                    *self.token_poison.lock().unwrap() = Some(e.message.clone());
                    json!({"error": e.message})
                } else {
                    raw_map.remove(&token);
                    json!({"error": e.message})
                }
            }
        }
    }

    fn op_token_revoke(&self, _agent: &str, policy: &Policy, fr: &Value) -> Value {
        if policy.agent() != Some("*") {
            return json!({"error": "admin required"});
        }
        if self.open_mode {
            return json!({"error": "unsupported in open mode"});
        }
        let path = match &self.tokens_path {
            Some(p) => p.clone(),
            None => return json!({"error": "token persistence not configured"}),
        };
        let target = match fr.get("token") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            _ => return json!({"error": "bad token"}),
        };
        let mut store = self.tokens.lock().unwrap();
        if self.token_poison.lock().unwrap().is_some() {
            return json!({"error": "token store poisoned"});
        }
        let mut raw_guard = self.tokens_raw.lock().unwrap();
        if raw_guard.is_none() {
            match crate::tokens::load_raw_root(&path) {
                Ok(m) => *raw_guard = Some(m),
                Err(e) => return json!({"error": e}),
            }
        }
        let raw_map = raw_guard.as_mut().unwrap();
        if raw_object_count(raw_map) != store.len() {
            return json!({"error": "token store out of sync"});
        }
        for (k, v) in raw_map.iter() {
            if v.is_object() && store.get(k).is_none() {
                return json!({"error": "token store out of sync"});
            }
        }
        if store.get(&target).is_none() {
            return json!({"ok": true, "revoked": false});
        }
        let saved = raw_map.get(&target).cloned();
        raw_map.remove(&target);
        let root_value = Value::Object(raw_map.clone().into_iter().collect());
        if let Err(e) = TokenStore::from_root(&root_value) {
            if let Some(v) = saved.clone() {
                raw_map.insert(target.clone(), v);
            }
            return json!({"error": e.to_string()});
        }
        let order_map = build_ordered_rates(raw_map, &store, None);
        let text = match crate::tokens::render_tokens_root_ordered(raw_map, &order_map) {
            Ok(t) => t,
            Err(e) => {
                if let Some(v) = saved.clone() {
                    raw_map.insert(target.clone(), v);
                }
                return json!({"error": e});
            }
        };
        let failpoint = self.tokens_failpoint.load(Ordering::SeqCst);
        match crate::tokens::persist_tokens_text(&path, &text, failpoint) {
            Ok(()) => match TokenStore::from_json_str(&text) {
                Ok(new_store) => {
                    *store = new_store;
                    // Prompt revocation for idle subscribers: drop subs
                    // + purge queued live (counted) so revoked live never
                    // delivers after commit. Tokens locks released first
                    // (no state -> tokens inversion; delivery uses snapshots).
                    drop(store);
                    drop(raw_guard);
                    let outboxes = self.subs.lock().unwrap().remove_token(&target);
                    for ob in outboxes {
                        ob.purge_live_with_accounting(&self.drops);
                    }
                    json!({"ok": true, "revoked": true})
                }
                Err(_) => {
                    *self.token_poison.lock().unwrap() = Some("reload failed".to_string());
                    if let Some(v) = saved.clone() {
                        raw_map.insert(target.clone(), v);
                    }
                    json!({"error": "token store reload failed"})
                }
            },
            Err(e) => {
                if e.post_rename_uncertain {
                    let committed = if let Ok(new_store) = TokenStore::from_json_str(&text) {
                        *store = new_store;
                        true
                    } else {
                        if let Some(v) = saved.clone() {
                            raw_map.insert(target.clone(), v);
                        }
                        false
                    };
                    *self.token_poison.lock().unwrap() = Some(e.message.clone());
                    let msg = e.message.clone();
                    if committed {
                        let target_c = target.clone();
                        drop(store);
                        drop(raw_guard);
                        let outboxes = self.subs.lock().unwrap().remove_token(&target_c);
                        for ob in outboxes {
                            ob.purge_live_with_accounting(&self.drops);
                        }
                    }
                    json!({"error": msg})
                } else {
                    if let Some(v) = saved.clone() {
                        raw_map.insert(target.clone(), v);
                    }
                    json!({"error": e.message})
                }
            }
        }
    }

    fn op_token_claim(&self, agent: &str, policy: &Policy, fr: &Value) -> Value {
        let claim_pat = policy.claim_pattern().map(|p| p.as_str()).unwrap_or("");
        if claim_pat.is_empty() {
            return json!({"error": "claim token required"});
        }
        if self.open_mode {
            return json!({"error": "unsupported in open mode"});
        }
        let path = match &self.tokens_path {
            Some(p) => p.clone(),
            None => return json!({"error": "token persistence not configured"}),
        };
        let now = self.clock_now();
        if !now.is_finite() {
            return json!({"error": "non-finite time"});
        }
        let wanted = fr.get("agent").and_then(|v| v.as_str()).unwrap_or("");
        if !crate::tokens::is_valid_agent_name(wanted) {
            return json!({"error": "bad agent name"});
        }
        let entry = crate::tokens::build_claim_entry(wanted);
        let new_policy = match Policy::from_json(&entry) {
            Ok(p) => p,
            Err(e) => return json!({"error": e.to_string()}),
        };
        let mut store = self.tokens.lock().unwrap();
        if self.token_poison.lock().unwrap().is_some() {
            return json!({"error": "token store poisoned"});
        }
        let mut raw_guard = self.tokens_raw.lock().unwrap();
        if raw_guard.is_none() {
            match crate::tokens::load_raw_root(&path) {
                Ok(m) => *raw_guard = Some(m),
                Err(e) => return json!({"error": e}),
            }
        }
        let raw_map = raw_guard.as_mut().unwrap();
        if let Err(e) = check_raw_store_sync_for_insert(raw_map, &store) {
            return json!({"error": e});
        }
        for v in raw_map.values() {
            if let Some(obj) = v.as_object() {
                if let Some(Value::String(a)) = obj.get("agent") {
                    if a == wanted {
                        return json!({"error": "name taken"});
                    }
                }
            }
        }
        {
            let mut presence = self.presence.lock().unwrap();
            presence.prune(now);
            if presence.contains(wanted) {
                return json!({"error": "name taken"});
            }
        }
        {
            let mut log = self.claim_log.lock().unwrap();
            let hist = log.entry(agent.to_string()).or_default();
            crate::tokens::prune_claim_history(hist, now);
            if hist.len() >= crate::tokens::CLAIM_MAX {
                return json!({"error": "claim rate limited (3/hour)"});
            }
        }
        let mut token = String::new();
        let mut found = false;
        for _ in 0..8 {
            let hex = match crate::tokens::secure_random_hex(crate::tokens::TOKEN_RANDOM_BYTES) {
                Ok(h) => h,
                Err(e) => return json!({"error": e}),
            };
            let candidate = crate::tokens::make_token(wanted, &hex);
            if store.get(&candidate).is_none() && !raw_map.contains_key(&candidate) {
                token = candidate;
                found = true;
                break;
            }
        }
        if !found {
            return json!({"error": "token collision, retry"});
        }
        raw_map.insert(token.clone(), entry.clone());
        let root_value = Value::Object(raw_map.clone().into_iter().collect());
        if let Err(e) = TokenStore::from_root(&root_value) {
            raw_map.remove(&token);
            return json!({"error": e.to_string()});
        }
        let order_map = build_ordered_rates(raw_map, &store, Some((token.as_str(), &new_policy)));
        let text = match crate::tokens::render_tokens_root_ordered(raw_map, &order_map) {
            Ok(t) => t,
            Err(e) => {
                raw_map.remove(&token);
                return json!({"error": e});
            }
        };
        let failpoint = self.tokens_failpoint.load(Ordering::SeqCst);
        match crate::tokens::persist_tokens_text(&path, &text, failpoint) {
            Ok(()) => match TokenStore::from_json_str(&text) {
                Ok(new_store) => {
                    *store = new_store;
                    {
                        let mut log = self.claim_log.lock().unwrap();
                        let hist = log.entry(agent.to_string()).or_default();
                        crate::tokens::prune_claim_history(hist, now);
                        hist.push(now);
                    }
                    if agent != wanted {
                        let mut presence = self.presence.lock().unwrap();
                        presence.prune(now);
                        presence.retire(agent, now);
                    }
                    json!({"ok": true, "token": token, "agent": wanted, "exp": Value::Null})
                }
                Err(_) => {
                    *self.token_poison.lock().unwrap() = Some("reload failed".to_string());
                    raw_map.remove(&token);
                    json!({"error": "token store reload failed"})
                }
            },
            Err(e) => {
                if e.post_rename_uncertain {
                    if let Ok(new_store) = TokenStore::from_json_str(&text) {
                        *store = new_store;
                    } else {
                        raw_map.remove(&token);
                    }
                    *self.token_poison.lock().unwrap() = Some(e.message.clone());
                    json!({"error": e.message})
                } else {
                    raw_map.remove(&token);
                    json!({"error": e.message})
                }
            }
        }
    }
}

/// Document-ordered `topic_rates` from a raw `token_issue` request line.
/// Returns `None` for missing/null (no override), `Some(pairs)` for
/// falsy-to-empty or object-to-document-order pairs (duplicates kept here,
/// collapsed last-value-first-position in `parse_rules_ordered`), `Err` for
/// truthy non-object shapes. The line already parsed as `Value` successfully
/// (caller checked), so a probe failure is a `topic_rates` shape error, not a
/// frame error. Diagnostics never echo the request (policy patterns may appear
/// in later validation, never secrets).
fn parse_issue_ordered_rates(line: &str) -> Result<Option<Vec<(String, Value)>>, String> {
    #[derive(serde::Deserialize)]
    struct Probe {
        #[serde(default)]
        topic_rates: Option<crate::rate::OrderedTopicRates>,
    }
    let probe: Probe =
        serde_json::from_str(line).map_err(|e| format!("topic_rates order parse failed: {e}"))?;
    Ok(probe.topic_rates.map(|o| o.0))
}

fn raw_object_count(raw: &BTreeMap<String, Value>) -> usize {
    raw.values().filter(|v| v.is_object()).count()
}

fn check_raw_store_sync_for_insert(
    raw: &BTreeMap<String, Value>,
    store: &TokenStore,
) -> Result<(), String> {
    if raw_object_count(raw) != store.len() {
        return Err("token store out of sync".to_string());
    }
    for (k, v) in raw {
        if v.is_object() && store.get(k).is_none() {
            return Err("token store out of sync".to_string());
        }
    }
    Ok(())
}

fn build_ordered_rates(
    raw: &BTreeMap<String, Value>,
    store: &TokenStore,
    extra: Option<(&str, &Policy)>,
) -> BTreeMap<String, Vec<(String, Value)>> {
    let mut out = BTreeMap::new();
    for (token, val) in raw {
        if !val.is_object() {
            continue;
        }
        let rules: Option<Vec<(String, f64)>> = if let Some((extra_tok, extra_pol)) = extra {
            if token == extra_tok {
                Some(
                    extra_pol
                        .rate_config()
                        .rules
                        .iter()
                        .map(|r| (r.pattern_raw.clone(), r.per_s))
                        .collect(),
                )
            } else {
                store.get(token).map(|p| {
                    p.rate_config()
                        .rules
                        .iter()
                        .map(|r| (r.pattern_raw.clone(), r.per_s))
                        .collect()
                })
            }
        } else {
            store.get(token).map(|p| {
                p.rate_config()
                    .rules
                    .iter()
                    .map(|r| (r.pattern_raw.clone(), r.per_s))
                    .collect()
            })
        };
        if let Some(rules) = rules {
            if !rules.is_empty() {
                let raw_map = val.get("topic_rates").and_then(|v| v.as_object());
                let mut pairs = Vec::with_capacity(rules.len());
                for (pat, per_s) in rules {
                    let v = raw_map
                        .and_then(|m| m.get(&pat))
                        .cloned()
                        .unwrap_or_else(|| json!(per_s));
                    pairs.push((pat, v));
                }
                out.insert(token.clone(), pairs);
            }
        }
    }
    out
}

/// Normalize optional correlation fields for idempotency equality:
/// missing (`None`) and explicit JSON null (`Some(Null)`) are the same
/// (WAL round-trip collapses both to `None`), so a retry that omits
/// `corr_id`/`reply_to` still matches an original that sent explicit
/// null, and vice versa. Anything else compares by value.
fn norm_corr(v: &Option<Value>) -> Option<&Value> {
    match v {
        None => None,
        Some(Value::Null) => None,
        Some(x) => Some(x),
    }
}

/// Python `if want` truthiness for artifact sha-want checks
/// (`broker.py:1103,1203`): `None`/`null`/`""`/`0`/`false`/`[]`/`{}`
/// skip the check; anything else must equal the computed sha.
fn py_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i != 0
            } else if let Some(u) = n.as_u64() {
                u != 0
            } else if let Some(f) = n.as_f64() {
                f != 0.0
            } else {
                false
            }
        }
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Fail-closed pre-append length: the rollback target for the next WAL
/// append. Only a missing file may mean zero (fresh WAL, nothing to roll
/// back); any other metadata error fails before any bytes are written so a
/// failed stat can never authorize a truncate-to-zero rollback that would
/// destroy existing history. Callers fail the op without poisoning (no
/// partial bytes exist yet).
pub fn pre_append_len(path: &Path) -> Result<u64, String> {
    match std::fs::metadata(path) {
        Ok(m) => Ok(m.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(format!("wal pre-length unavailable: {e}")),
    }
}

/// WAL sink that fsyncs every grant record before ack (broker-enforced
/// durability) with the server's robust rollback/poison discipline.
/// A write error aborts the op with state untouched.
struct WalSink {
    server: Server,
}

impl ClaimWal for WalSink {
    fn append(&mut self, rec: WalClaim) -> Result<(), String> {
        let v = match &rec {
            WalClaim::Acquire {
                resource,
                owner,
                token,
                fencing,
                acquired_at,
                expires_at,
                idem,
                ttl_ms,
                renew,
            } => {
                json!({"t": "claim_acquire", "resource": resource, "owner": owner, "token": token, "fencing": fencing, "acquired_at": acquired_at, "expires_at": expires_at, "idem": idem, "ttl_ms": ttl_ms, "renew": renew})
            }
            WalClaim::Release { resource, fencing } => {
                json!({"t": "claim_release", "resource": resource, "fencing": fencing})
            }
        };
        self.server.append_value_robust(&v)
    }
}

fn claim_err(e: ClaimError) -> Value {
    let mut v = json!({"ok": false, "error": e.error});
    let o = v.as_object_mut().unwrap();
    if e.conflict {
        o.insert("conflict".into(), json!(true));
    }
    if e.retired {
        o.insert("retired".into(), json!(true));
    }
    if e.expired {
        o.insert("expired".into(), json!(true));
    }
    if e.capacity {
        o.insert("capacity".into(), json!(true));
    }
    if let Some(h) = e.holder {
        o.insert("holder".into(), json!(h));
    }
    if let Some(t) = e.token {
        o.insert("token".into(), json!(t));
    }
    if let Some(f) = e.fencing {
        o.insert("fencing".into(), json!(f));
    }
    if let Some(x) = e.expires_at {
        o.insert("expires_at".into(), json!(x));
    }
    v
}

/// Bounded line reader: never buffers more than `limit + chunk` bytes per
/// connection, so a delimiter-less flood cannot grow memory without bound.
enum FrameRead {
    Line(String),
    Eof,
    BadUtf8,
    TooLarge,
}

fn read_frame<R: std::io::Read>(r: &mut BufReader<R>, limit: usize) -> FrameRead {
    use std::io::BufRead;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let filled = match r.fill_buf() {
            Ok(f) => f,
            Err(_) => return FrameRead::Eof,
        };
        if filled.is_empty() {
            return FrameRead::Eof; // disconnect; partial bytes are dropped
        }
        match filled.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                let take = pos + 1;
                if buf.len() + take > limit {
                    return FrameRead::TooLarge;
                }
                buf.extend_from_slice(&filled[..take]);
                r.consume(take);
                return match String::from_utf8(buf) {
                    Ok(s) => FrameRead::Line(s),
                    Err(_) => FrameRead::BadUtf8,
                };
            }
            None => {
                if buf.len() + filled.len() > limit {
                    return FrameRead::TooLarge;
                }
                let n = filled.len();
                buf.extend_from_slice(filled);
                r.consume(n);
            }
        }
    }
}

/// Merge `req_id` with a control payload into one response frame
/// (`{"req_id":..., ...resp}`), mirroring the transitional broker.
fn with_req_id(req_id: &Value, resp: &Value) -> Value {
    let mut out = json!({"req_id": req_id});
    if let Some(obj) = out.as_object_mut() {
        if let Some(robj) = resp.as_object() {
            for (k, v) in robj {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    out
}

/// Per-connection writer: drains the shared outbox FIFO to the socket
/// with blocking writes (backpressure, no timeout, matching Python
/// `sender_loop` drain). Control receipts always send; live + replay
/// data send only when current delivery policy allows
/// ([`SubsRegistry::allows_delivery`] against the per-connection snapshot
/// + current clock, checked at the admission linearization point below).
/// Denied live counts as dropped (per-sub + global); denied replay drops
/// silently (replays counts queued only). On write failure (peer gone)
/// closes the outbox to unblock reliable waiters and exits. Serialization
/// failure skips the frame (non-finite clocks are fail-closed at the op
/// layer, so this is unreachable in practice) rather than panicking the
/// thread.
///
/// Concurrency contract: pop (queue lock, typed [`OutFrame`] retained) ->
/// preparatory delay + JSON serialization (no locks) -> admission check
/// (registry lock briefly, queue lock released) -> blocking socket write
/// (no locks). The admission check just before the first socket write is
/// the admission linearization point: any policy change or expiry
/// committing before it is enforced; a change committing after it may
/// still deliver this one in-flight frame. Global registry/token locks
/// stay out of blocking socket I/O. Per-connection ordering could narrow
/// the in-flight window further, but that is a separate design. Bytes
/// already accepted by the socket (even partially) cannot be recalled; no
/// immediate delivery-stop barrier is promised.
fn writer_loop(
    mut writer: WireStream,
    outbox: std::sync::Arc<ConnOutbox>,
    delay_us: std::sync::Arc<AtomicU64>,
    subs: std::sync::Arc<std::sync::Mutex<SubsRegistry>>,
    conn_id: u64,
    fixed_now: std::sync::Arc<std::sync::Mutex<Option<f64>>>,
    drops: std::sync::Arc<AtomicU64>,
) {
    loop {
        outbox.wait_while_held();
        let popped = match outbox.pop_for_writer() {
            Some(f) => f,
            None => break,
        };
        // Preparatory work first (no authorization yet): optional test
        // delay, then JSON serialization. The typed `OutFrame` (with
        // `sub_id`/counters) is retained across both so the admission
        // check below still has ownership + drop accounting.
        let d = delay_us.load(Ordering::SeqCst);
        if d > 0 {
            std::thread::sleep(std::time::Duration::from_micros(d));
        }
        let frame_ref: &serde_json::Value = match &popped {
            OutFrame::Control(v) => v,
            OutFrame::Live { frame, .. } => frame,
            OutFrame::Replay { frame, .. } => frame,
        };
        let mut bytes = match serde_json::to_vec(frame_ref) {
            Ok(mut b) => {
                b.push(b'\n');
                b
            }
            Err(_) => continue,
        };
        // Admission linearization point: current delivery policy just
        // before the first socket write (fresh clock, brief registry lock,
        // queue lock released). Control always sends; data denies fail
        // closed (missing snapshot, unprovable/expired time, lost cover).
        let allowed = match &popped {
            OutFrame::Control(_) => true,
            OutFrame::Live { sub_id, .. } => {
                let now = fixed_now.lock().unwrap().unwrap_or_else(now);
                subs.lock().unwrap().allows_delivery(conn_id, sub_id, now)
            }
            OutFrame::Replay { sub_id, .. } => {
                let now = fixed_now.lock().unwrap().unwrap_or_else(now);
                subs.lock().unwrap().allows_delivery(conn_id, sub_id, now)
            }
        };
        if !allowed {
            if let OutFrame::Live { counters, .. } = &popped {
                counters.dropped.fetch_add(1, Ordering::SeqCst);
                drops.fetch_add(1, Ordering::SeqCst);
            }
            continue;
        }
        // `write_all` may write partially internally; loop on
        // `Interrupted` like the client transport (same-byte progress,
        // not a resend). Any other error means the peer is gone.
        let mut off = 0;
        let failed = loop {
            match writer.write(&bytes[off..]) {
                Ok(0) => break true,
                Ok(n) => {
                    off += n;
                    if off >= bytes.len() {
                        match writer.flush() {
                            Ok(()) => break false,
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(_) => break true,
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break true,
            }
        };
        if failed {
            outbox.close();
            break;
        }
        let _ = &mut bytes;
    }
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn nanoid() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    (now().to_bits(), std::process::id(), h.finish()).hash(&mut h);
    format!("{:016x}{:016x}", h.finish(), now().to_bits())
}

/// Finite client RPC bounds (documented; no live tuning knobs).
///
/// - Dial: DNS resolution (`ToSocketAddrs`) is platform-blocking and NOT
///   bounded by [`CLIENT_CONNECT_TIMEOUT`]; each resolved address then gets
///   up to that timeout via `connect_timeout`. Worst-case total dial time is
///   `addrs.len() * CLIENT_CONNECT_TIMEOUT` plus unbounded DNS. IP literals
///   resolve to one address, so exactly that per-address bound (no DNS).
/// - Each RPC: [`CLIENT_RPC_TIMEOUT`] overall deadline covering the
///   deadline-aware write plus the full reply read. The write loop resets the
///   socket write timeout to the remaining budget each iteration (resuming
///   partial progress, retrying only `Interrupted` on the same bytes) and the
///   read loop tightens similarly with an absolute `Instant` check, so a
///   slow-draining peer or slow-drip server cannot extend past the bound.
/// - Reply frame: [`CLIENT_RESP_LIMIT`] bytes max per response line.
///   Legitimate history pages are at most 4 MiB plus JSON overhead, so the
///   8 MiB cap preserves protocol behavior while bounding memory.
///
/// Every RPC makes exactly one attempt and never retries: a timed-out
/// mutation (post/kv-put/claim) has uncertain status — the broker may have
/// committed it — so callers must reconcile by reading state, never by
/// blindly resending. `Interrupted` resume inside one write is transport
/// progress on the same bytes, not a second attempt. Diagnostics are fixed or
/// bounded and never echo server-controlled text: hello failures return a
/// constant, `req_id` mismatches name numeric ids but describe non-numeric
/// ids by type/length only. Non-object `rpc` input returns `InvalidInput`.
/// Error strings never contain the auth token.
pub const CLIENT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const CLIENT_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const CLIENT_RESP_LIMIT: usize = 8 * 1024 * 1024;

/// Aggregate serialized bytes retained by a streaming client while a
/// control RPC receives interleaved deliveries. Frames also have a count
/// cap sufficient for one maximum replay and one outbound live queue.
pub const CLIENT_STREAM_BUFFER_BYTES: usize = CLIENT_RESP_LIMIT;
pub const CLIENT_STREAM_BUFFER_FRAMES: usize =
    crate::subs::SUBS_REPLAY_CAP + crate::subs::SUBS_QUEUE_MAX;

/// Minimal blocking client for tests and tooling.
///
/// Single-attempt RPC with finite deadlines, bounded reply frames, and
/// strict `req_id` matching. Frame-level broker errors (`frame exceeds
/// byte limit`, `frame is not valid UTF-8`) intentionally carry a null
/// `req_id` and are accepted as real error replies; every other response
/// must echo the sent numeric id exactly.
pub struct Client {
    reader: BufReader<WireStream>,
    writer: WireStream,
    next: u64,
    rpc_timeout: std::time::Duration,
    resp_limit: usize,
}

impl Client {
    /// Dial TCP `addr` (`HOST:PORT`) plus hello. Preserved TCP behavior:
    /// same DNS/connect/RPC deadlines, reply cap, and `req_id` matching.
    pub fn connect(addr: &str, agent: &str, token: &str) -> std::io::Result<Self> {
        let stream = Self::dial(addr, CLIENT_CONNECT_TIMEOUT)?;
        let mut c = Self::wrap(
            WireStream::Tcp(stream),
            CLIENT_RPC_TIMEOUT,
            CLIENT_RESP_LIMIT,
        )?;
        let resp = c.rpc(&json!({"op": "hello", "agent": agent, "token": token}))?;
        if resp.get("ok") != Some(&json!(true)) {
            // Fixed diagnostic: never echo the hello reply, which a hostile
            // or buggy broker could fill with the supplied credential.
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "hello failed: auth refused",
            ));
        }
        Ok(c)
    }

    /// Dial Unix socket `path` plus hello (only on `cfg(unix)`). Same RPC
    /// deadlines, reply cap, and `req_id` matching as TCP. The dial itself
    /// is a blocking local `connect` with no timeout (no DNS, typically
    /// immediate); read/write deadlines still bound every RPC. Never
    /// silently falls back to TCP: a missing/refused socket is an error.
    #[cfg(unix)]
    pub fn connect_unix(path: &Path, agent: &str, token: &str) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        let mut c = Self::wrap(
            WireStream::Unix(stream),
            CLIENT_RPC_TIMEOUT,
            CLIENT_RESP_LIMIT,
        )?;
        let resp = c.rpc(&json!({"op": "hello", "agent": agent, "token": token}))?;
        if resp.get("ok") != Some(&json!(true)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "hello failed: auth refused",
            ));
        }
        Ok(c)
    }

    /// Connect without hello (tests unauthenticated paths).
    pub fn raw(addr: &str) -> std::io::Result<Self> {
        let stream = Self::dial(addr, CLIENT_CONNECT_TIMEOUT)?;
        Self::wrap(
            WireStream::Tcp(stream),
            CLIENT_RPC_TIMEOUT,
            CLIENT_RESP_LIMIT,
        )
    }

    /// Connect to a Unix socket without hello (only on `cfg(unix)`).
    #[cfg(unix)]
    pub fn raw_unix(path: &Path) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        Self::wrap(
            WireStream::Unix(stream),
            CLIENT_RPC_TIMEOUT,
            CLIENT_RESP_LIMIT,
        )
    }

    /// Wrap an already-connected owned TCP stream (no dial, no DNS, no
    /// thread). The caller owns the `connect_timeout` bound; this applies
    /// `rpc_timeout` to all reads/writes and uses [`CLIENT_RESP_LIMIT`].
    /// Used by the scheduler status transport for IP-literal-only bounded
    /// connects. Preserved: still takes `TcpStream`.
    pub fn from_connected_stream(
        stream: TcpStream,
        rpc_timeout: std::time::Duration,
    ) -> std::io::Result<Self> {
        Self::wrap(WireStream::Tcp(stream), rpc_timeout, CLIENT_RESP_LIMIT)
    }

    /// Wrap an already-connected owned Unix stream (only on `cfg(unix)`).
    #[cfg(unix)]
    pub fn from_connected_unix_stream(
        stream: UnixStream,
        rpc_timeout: std::time::Duration,
    ) -> std::io::Result<Self> {
        Self::wrap(WireStream::Unix(stream), rpc_timeout, CLIENT_RESP_LIMIT)
    }

    /// Test hook: shrink the per-RPC deadline (production uses
    /// [`CLIENT_RPC_TIMEOUT`).
    pub fn set_rpc_timeout(&mut self, timeout: std::time::Duration) -> std::io::Result<()> {
        self.rpc_timeout = timeout;
        Self::apply_timeouts(self.reader.get_ref(), &self.writer, timeout)
    }

    /// Test hook: shrink the per-response frame cap (production uses
    /// [`CLIENT_RESP_LIMIT`).
    pub fn set_response_limit(&mut self, limit: usize) {
        self.resp_limit = limit;
    }

    fn dial(addr: &str, timeout: std::time::Duration) -> std::io::Result<TcpStream> {
        use std::net::ToSocketAddrs;
        // DNS is platform-blocking (no timeout here); each resolved address
        // then gets `timeout`. Worst case is addrs.len() * timeout plus DNS.
        let addrs: Vec<_> = addr.to_socket_addrs()?.collect();
        let mut last_err = std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unresolvable broker address",
        );
        if addrs.is_empty() {
            return Err(last_err);
        }
        for a in addrs {
            match TcpStream::connect_timeout(&a, timeout) {
                Ok(s) => return Ok(s),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn wrap(
        stream: WireStream,
        rpc_timeout: std::time::Duration,
        resp_limit: usize,
    ) -> std::io::Result<Self> {
        let reader = BufReader::new(stream.try_clone()?);
        let c = Client {
            reader,
            writer: stream,
            next: 1,
            rpc_timeout,
            resp_limit,
        };
        Self::apply_timeouts(c.reader.get_ref(), &c.writer, rpc_timeout)?;
        Ok(c)
    }

    fn apply_timeouts(
        reader_inner: &WireStream,
        writer: &WireStream,
        timeout: std::time::Duration,
    ) -> std::io::Result<()> {
        reader_inner.set_read_timeout(Some(timeout))?;
        reader_inner.set_write_timeout(Some(timeout))?;
        writer.set_read_timeout(Some(timeout))?;
        writer.set_write_timeout(Some(timeout))?;
        Ok(())
    }

    /// One request, one bounded reply, no retries. On timeout the mutation
    /// status (if any) is uncertain: the caller must reconcile by reading
    /// broker state, never by resending.
    pub fn rpc(&mut self, req: &Value) -> std::io::Result<Value> {
        if req.as_object().is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rpc request must be a JSON object",
            ));
        }
        let sent = self.next;
        let mut obj = req.clone();
        // Safe: object shape checked above; never touches the wire on bad input.
        obj.as_object_mut()
            .expect("rpc object checked")
            .insert("req_id".into(), json!(sent));
        self.next += 1;
        let mut bytes = serde_json::to_vec(&obj).unwrap();
        bytes.push(b'\n');
        self.rpc_send_recv(bytes, sent)
    }

    /// Ordered `token_issue` RPC for CLI flag order (first-match policy).
    /// `req` is the base request without `topic_rates` (any `topic_rates` or
    /// `req_id` members inside are ignored and replaced); `ordered` is the
    /// deduped `(pattern, rate)` pairs in caller declaration order
    /// (last-value-first-position, via `rate::dedup_ordered_pairs`).
    /// Top-level fields serialize in sorted order (semantics order-independent);
    /// only `topic_rates` keeps the supplied order. Same deadlines, reply cap,
    /// `req_id` matching, and frame-error protocol as [`Client::rpc`].
    /// Diagnostics never echo the request or the credential.
    pub fn rpc_with_ordered_topic_rates(
        &mut self,
        req: &Value,
        ordered: &[(String, Value)],
    ) -> std::io::Result<Value> {
        let obj = req.as_object().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rpc request must be a JSON object",
            )
        })?;
        let sent = self.next;
        self.next += 1;
        let encode = |v: &Value| {
            serde_json::to_string(v).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("rpc encode failed: {e}"),
                )
            })
        };
        let mut keys: Vec<&String> = obj
            .keys()
            .filter(|k| k.as_str() != "topic_rates" && k.as_str() != "req_id")
            .collect();
        keys.sort();
        let mut parts: Vec<String> = Vec::with_capacity(keys.len() + 2);
        for k in keys {
            let v = obj.get(k).unwrap_or(&Value::Null);
            let kj = encode(&Value::String(k.clone()))?;
            let vj = encode(v)?;
            parts.push(format!("{kj}:{vj}"));
        }
        if !ordered.is_empty() {
            let mut tr = String::from("{");
            for (i, (pat, val)) in ordered.iter().enumerate() {
                if i > 0 {
                    tr.push(',');
                }
                let pj = encode(&Value::String(pat.clone()))?;
                let vj = encode(val)?;
                tr.push_str(&format!("{pj}:{vj}"));
            }
            tr.push('}');
            parts.push(format!("\"topic_rates\":{tr}"));
        }
        parts.push(format!("\"req_id\":{sent}"));
        let mut bytes = format!("{{{}}}", parts.join(",")).into_bytes();
        bytes.push(b'\n');
        self.rpc_send_recv(bytes, sent)
    }

    /// Shared send-one-receive-one with deadlines, reply cap, and `req_id`
    /// matching. `bytes` must already end with `\n` and embed `sent`.
    fn rpc_send_recv(&mut self, bytes: Vec<u8>, sent: u64) -> std::io::Result<Value> {
        let deadline = std::time::Instant::now() + self.rpc_timeout;
        if let Err(e) = self.write_all_deadline(&bytes, deadline) {
            return Err(Self::map_timeout(e, "rpc write timed out"));
        }
        let line = self.read_response_line(deadline)?;
        let resp: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bad response: reply is not valid JSON",
                ))
            }
        };
        match resp.get("req_id") {
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("response missing req_id: expected {sent}"),
            )),
            Some(Value::Null) => {
                // Preserved frame-error protocol: the broker answers
                // delimiter/UTF-8 violations with a null id, then (for
                // oversize) drops the connection. Accept those two errors
                // verbatim; any other null id is a mismatch.
                let err = resp.get("error").and_then(|e| e.as_str()).unwrap_or("");
                if err == "frame exceeds byte limit" || err == "frame is not valid UTF-8" {
                    return Ok(resp);
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("response req_id mismatch: expected {sent}, got null"),
                ))
            }
            Some(got) if *got == json!(sent) => Ok(resp),
            Some(got) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "response req_id mismatch: expected {sent}, got {}",
                    describe_req_id(got)
                ),
            )),
        }
    }

    /// Deadline-aware write: each `write`/`flush` call gets the remaining
    /// budget until `deadline`, partial progress resumes, `Interrupted`
    /// retries the same bytes, and expiry returns `TimedOut`. Restores the
    /// full RPC write timeout before returning so later RPCs start fresh.
    /// This keeps the overall [`CLIENT_RPC_TIMEOUT`] claim covering slow
    /// drains, not just the read half. Single attempt: no resend on timeout.
    fn write_all_deadline(
        &mut self,
        bytes: &[u8],
        deadline: std::time::Instant,
    ) -> std::io::Result<()> {
        let full = self.rpc_timeout;
        let done = |this: &mut Self, r: std::io::Result<()>| {
            let _ = this.writer.set_write_timeout(Some(full));
            r
        };
        let mut off = 0;
        while off < bytes.len() {
            if std::time::Instant::now() >= deadline {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rpc write timed out",
                    )),
                );
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rpc write timed out",
                    )),
                );
            }
            self.writer.set_write_timeout(Some(remaining))?;
            match self.writer.write(&bytes[off..]) {
                Ok(0) => {
                    return done(
                        self,
                        Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "connection closed during write",
                        )),
                    );
                }
                Ok(n) => off += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return done(self, Err(e)),
            }
        }
        loop {
            if std::time::Instant::now() >= deadline {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rpc write timed out",
                    )),
                );
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rpc write timed out",
                    )),
                );
            }
            self.writer.set_write_timeout(Some(remaining))?;
            match self.writer.flush() {
                Ok(()) => return done(self, Ok(())),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return done(self, Err(e)),
            }
        }
    }

    /// Bounded line read: never buffers more than `resp_limit` bytes, and
    /// never blocks past `deadline` (socket timeouts tighten to the
    /// remaining budget each chunk, so silent or slow-drip servers always
    /// terminate). Restores the full RPC timeout before returning.
    fn read_response_line(&mut self, deadline: std::time::Instant) -> std::io::Result<String> {
        let limit = self.resp_limit;
        let timeout = self.rpc_timeout;
        let done = |this: &mut Self, r: std::io::Result<String>| {
            let _ = this.reader.get_mut().set_read_timeout(Some(timeout));
            r
        };
        let mut buf: Vec<u8> = Vec::new();
        loop {
            if std::time::Instant::now() >= deadline {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rpc timed out waiting for response",
                    )),
                );
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            self.reader.get_mut().set_read_timeout(Some(remaining))?;
            // Scope the fill_buf borrow: copy the chunk, then consume.
            let (chunk, take, newline) = {
                let filled = match self.reader.fill_buf() {
                    Ok(f) => f,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        return done(
                            self,
                            Err(Self::map_timeout(e, "rpc timed out waiting for response")),
                        )
                    }
                };
                if filled.is_empty() {
                    if buf.is_empty() {
                        // Server closed without a response frame (e.g. after
                        // an oversize frame): a transport error, not a
                        // synthesized response, so callers can tell "no
                        // reply" apart from a real error line.
                        return done(
                            self,
                            Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "connection closed without response",
                            )),
                        );
                    }
                    return done(
                        self,
                        Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "connection closed mid-response (partial reply)",
                        )),
                    );
                }
                match filled.iter().position(|&b| b == b'\n') {
                    Some(pos) => {
                        let take = pos + 1;
                        (filled[..take].to_vec(), take, true)
                    }
                    None => (filled.to_vec(), filled.len(), false),
                }
            };
            if buf.len() + chunk.len() > limit {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("response exceeds byte limit ({limit} bytes)"),
                    )),
                );
            }
            buf.extend_from_slice(&chunk);
            self.reader.consume(take);
            if newline {
                let out = match String::from_utf8(buf) {
                    Ok(s) => s,
                    Err(_) => {
                        return done(
                            self,
                            Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "bad response: reply is not valid UTF-8",
                            )),
                        )
                    }
                };
                return done(self, Ok(out));
            }
        }
    }

    /// Map socket-timeout kinds to `TimedOut` with a stable message; pass
    /// every other error through untouched.
    fn map_timeout(e: std::io::Error, msg: &str) -> std::io::Error {
        if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
            std::io::Error::new(std::io::ErrorKind::TimedOut, msg.to_string())
        } else {
            e
        }
    }
}

/// Single-threaded streaming connection: one socket, sequential
/// `subscribe`/`recv`/`unsubscribe`, no reader thread. Replay frames
/// arrive before the `subscribe` reply (matching Python order); they are
/// buffered as early live and drained by `recv` in order. Live frames
/// encountered while waiting for `unsubscribe` replies are buffered for
/// other subs (same-sub frames are discarded for isolation). Control
/// responses must match the one in-flight RPC; unsolicited controls are
/// rejected instead of being saved for a request that was never sent.
/// Interleaved deliveries have aggregate byte and frame bounds. Timeouts
/// are `TimedOut` (callers distinguish timeout
/// from failure); diagnostics never echo the token.
pub struct StreamingConn {
    reader: BufReader<WireStream>,
    writer: WireStream,
    next: u64,
    rpc_timeout: std::time::Duration,
    resp_limit: usize,
    early: std::collections::VecDeque<(Value, usize)>,
    early_bytes: usize,
    subs: std::collections::HashSet<String>,
    deadline: Option<std::time::Instant>,
}

impl StreamingConn {
    /// Dial TCP + hello (fails closed on refusal, never echoes the token).
    /// Uses [`CLIENT_CONNECT_TIMEOUT`] per address and
    /// [`CLIENT_RPC_TIMEOUT`] overall for hello. Preserved TCP behavior.
    pub fn connect(addr: &str, agent: &str, token: &str) -> std::io::Result<Self> {
        let stream = Client::dial(addr, CLIENT_CONNECT_TIMEOUT)?;
        let mut c = Self::wrap(
            WireStream::Tcp(stream),
            CLIENT_RPC_TIMEOUT,
            CLIENT_RESP_LIMIT,
        )?;
        let resp = c.rpc_wait(&json!({"op": "hello", "agent": agent, "token": token}))?;
        if resp.get("ok") != Some(&json!(true)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "hello failed: auth refused",
            ));
        }
        Ok(c)
    }

    /// Dial Unix socket + hello (only on `cfg(unix)`). Same RPC bounds as
    /// TCP; the dial itself is blocking local `connect` with no timeout.
    /// Never silently falls back to TCP.
    #[cfg(unix)]
    pub fn connect_unix(path: &Path, agent: &str, token: &str) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        let mut c = Self::wrap(
            WireStream::Unix(stream),
            CLIENT_RPC_TIMEOUT,
            CLIENT_RESP_LIMIT,
        )?;
        let resp = c.rpc_wait(&json!({"op": "hello", "agent": agent, "token": token}))?;
        if resp.get("ok") != Some(&json!(true)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "hello failed: auth refused",
            ));
        }
        Ok(c)
    }

    fn wrap(
        stream: WireStream,
        rpc_timeout: std::time::Duration,
        resp_limit: usize,
    ) -> std::io::Result<Self> {
        let reader = BufReader::new(stream.try_clone()?);
        let c = StreamingConn {
            reader,
            writer: stream,
            next: 1,
            rpc_timeout,
            resp_limit,
            early: std::collections::VecDeque::new(),
            early_bytes: 0,
            subs: std::collections::HashSet::new(),
            deadline: None,
        };
        Client::apply_timeouts(c.reader.get_ref(), &c.writer, rpc_timeout)?;
        Ok(c)
    }

    /// Test hook: shrink deadlines/frame cap (production uses the
    /// `CLIENT_*` constants).
    pub fn set_rpc_timeout(&mut self, timeout: std::time::Duration) -> std::io::Result<()> {
        self.rpc_timeout = timeout;
        Client::apply_timeouts(self.reader.get_ref(), &self.writer, timeout)
    }

    pub fn set_response_limit(&mut self, limit: usize) {
        self.resp_limit = limit;
    }

    /// Cap all subsequent control RPCs and receive waits at the same
    /// absolute deadline. Each RPC still keeps its smaller per-RPC bound.
    pub fn set_deadline(&mut self, deadline: std::time::Instant) {
        self.deadline = Some(deadline);
    }

    fn operation_deadline(
        &self,
        budget: std::time::Duration,
    ) -> std::io::Result<std::time::Instant> {
        let local = std::time::Instant::now()
            .checked_add(budget)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "deadline outside clock range",
                )
            })?;
        Ok(self.deadline.map_or(local, |outer| outer.min(local)))
    }

    /// Subscribe with `from_seq`/`tail` replay: returns
    /// `(sub_id, replayed, cursor)`. Buffers replay + interleaved live
    /// for `recv`. Overall deadline is `rpc_timeout`.
    pub fn subscribe(
        &mut self,
        pattern: &str,
        from_seq: u64,
        tail: u64,
    ) -> std::io::Result<(String, u64, Option<Value>)> {
        let mut op = json!({"op": "subscribe", "pattern": pattern, "from_seq": from_seq});
        if tail > 0 {
            op["tail"] = json!(tail);
        }
        let resp = self.rpc_wait(&op)?;
        if let Some(err) = resp.get("error") {
            let msg = err.as_str().unwrap_or("subscribe failed");
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                msg.to_string(),
            ));
        }
        let sub_id = resp
            .get("sub_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "subscribe response missing sub_id",
                )
            })?
            .to_string();
        let replayed = resp.get("replayed").and_then(|v| v.as_u64()).unwrap_or(0);
        let cursor = resp.get("cursor").cloned();
        self.subs.insert(sub_id.clone());
        Ok((sub_id, replayed, cursor))
    }

    /// Next live delivery frame (`{"event":"msg","sub_id":..,"topic":..,
    /// `"msg":..}`), draining early buffers first. `timeout=None` waits up
    /// to `rpc_timeout`; `Some(d)` waits up to `d`. Returns `TimedOut` on
    /// expiry (callers map to exit 0 for `--timeout`), `InvalidData` on
    /// null-id frame errors, `UnexpectedEof` on close.
    pub fn recv(&mut self, timeout: Option<std::time::Duration>) -> std::io::Result<Value> {
        if self
            .deadline
            .is_some_and(|end| std::time::Instant::now() >= end)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "stream deadline reached",
            ));
        }
        if let Some((fr, bytes)) = self.early.pop_front() {
            self.early_bytes -= bytes;
            return Ok(fr);
        }
        let budget = timeout.unwrap_or(self.rpc_timeout);
        let deadline = self.operation_deadline(budget)?;
        loop {
            let line = self.read_frame_line(deadline)?;
            let fr: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if fr.get("event") == Some(&json!("msg")) {
                return Ok(fr);
            }
            if let Some(rid) = fr.get("req_id") {
                if rid.is_null() {
                    let err = fr.get("error").and_then(|e| e.as_str()).unwrap_or("");
                    if err == "frame exceeds byte limit" || err == "frame is not valid UTF-8" {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("server frame error: {err}"),
                        ));
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unexpected null req_id control during stream",
                    ));
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected control response without an in-flight RPC",
                ));
            }
            // No `event` and no `req_id`: skip (never a valid delivery).
            continue;
        }
    }

    /// Unsubscribe one owned id (idempotent ok, even for unknown/foreign
    /// ids). Discards buffered + in-flight live for `sub_id` (isolation);
    /// buffers live for other subs. Overall deadline is `rpc_timeout`.
    pub fn unsubscribe(&mut self, sub_id: &str) -> std::io::Result<Value> {
        let resp = self.rpc_wait(&json!({"op": "unsubscribe", "sub_id": sub_id}))?;
        self.subs.remove(sub_id);
        self.early
            .retain(|(fr, _)| fr.get("sub_id").and_then(|v| v.as_str()) != Some(sub_id));
        self.early_bytes = self.early.iter().map(|(_, bytes)| bytes).sum();
        Ok(resp)
    }

    fn buffer_delivery(&mut self, frame: Value, bytes: usize) -> std::io::Result<()> {
        let total = self.early_bytes.checked_add(bytes).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stream buffer size overflow",
            )
        })?;
        if self.early.len() >= CLIENT_STREAM_BUFFER_FRAMES || total > CLIENT_STREAM_BUFFER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stream delivery buffer limit reached; delivery is incomplete",
            ));
        }
        self.early.push_back((frame, bytes));
        self.early_bytes = total;
        Ok(())
    }

    /// One control RPC on a streaming connection (e.g. `post` for
    /// request/reply), buffering interleaved live for later `recv`.
    /// Returns the control reply verbatim (caller checks `error`/`ok`).
    /// Overall deadline is `rpc_timeout`; on timeout the mutation status
    /// (if any) is uncertain and the caller must reconcile by reading
    /// broker state, never by resending. Immediate live arriving during
    /// the RPC stays in `early` so a correlated reply is not missed.
    pub fn rpc(&mut self, req: &Value) -> std::io::Result<Value> {
        self.rpc_wait(req)
    }

    /// One request, one matching control reply, buffering interleaved
    /// live (replay-before-reply order). Returns the control `Value`
    /// verbatim (caller checks `error`/`ok`). Overall deadline is
    /// `rpc_timeout`; buffered live stays in `early` for `recv`.
    fn rpc_wait(&mut self, req: &Value) -> std::io::Result<Value> {
        // Establish the deadline before cloning/serializing the request.
        // Serialization must not reset the connection's outer deadline.
        let deadline = self.operation_deadline(self.rpc_timeout)?;
        if req.as_object().is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rpc request must be a JSON object",
            ));
        }
        let sent = self.next;
        self.next += 1;
        let mut obj = req.clone();
        obj.as_object_mut()
            .expect("rpc object checked")
            .insert("req_id".into(), json!(sent));
        let mut bytes = serde_json::to_vec(&obj).unwrap();
        bytes.push(b'\n');
        self.write_all_deadline(&bytes, deadline)
            .map_err(|e| Client::map_timeout(e, "rpc write timed out"))?;
        loop {
            let line = self.read_frame_line(deadline)?;
            let fr: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if fr.get("event") == Some(&json!("msg")) {
                self.buffer_delivery(fr, line.len())?;
                continue;
            }
            match fr.get("req_id") {
                None => continue,
                Some(Value::Null) => {
                    let err = fr.get("error").and_then(|e| e.as_str()).unwrap_or("");
                    if err == "frame exceeds byte limit" || err == "frame is not valid UTF-8" {
                        return Ok(fr);
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("response req_id mismatch: expected {sent}, got null"),
                    ));
                }
                Some(got) if *got == json!(sent) => return Ok(fr),
                Some(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response req_id does not match the in-flight RPC",
                    ))
                }
            }
        }
    }

    fn write_all_deadline(
        &mut self,
        bytes: &[u8],
        deadline: std::time::Instant,
    ) -> std::io::Result<()> {
        let full = self.rpc_timeout;
        let done = |this: &mut Self, r: std::io::Result<()>| {
            let _ = this.writer.set_write_timeout(Some(full));
            r
        };
        let mut off = 0;
        while off < bytes.len() {
            if std::time::Instant::now() >= deadline {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rpc write timed out",
                    )),
                );
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rpc write timed out",
                    )),
                );
            }
            self.writer.set_write_timeout(Some(remaining))?;
            match self.writer.write(&bytes[off..]) {
                Ok(0) => {
                    return done(
                        self,
                        Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "connection closed during write",
                        )),
                    )
                }
                Ok(n) => off += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return done(self, Err(e)),
            }
        }
        loop {
            if std::time::Instant::now() >= deadline {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rpc write timed out",
                    )),
                );
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "rpc write timed out",
                    )),
                );
            }
            self.writer.set_write_timeout(Some(remaining))?;
            match self.writer.flush() {
                Ok(()) => return done(self, Ok(())),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return done(self, Err(e)),
            }
        }
    }

    fn read_frame_line(&mut self, deadline: std::time::Instant) -> std::io::Result<String> {
        let limit = self.resp_limit;
        let timeout = self.rpc_timeout;
        let done = |this: &mut Self, r: std::io::Result<String>| {
            let _ = this.reader.get_mut().set_read_timeout(Some(timeout));
            r
        };
        let mut buf: Vec<u8> = Vec::new();
        loop {
            if std::time::Instant::now() >= deadline {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "stream timed out waiting for frame",
                    )),
                );
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            self.reader.get_mut().set_read_timeout(Some(remaining))?;
            let (chunk, take, newline) = {
                let filled = match self.reader.fill_buf() {
                    Ok(f) => f,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        return done(
                            self,
                            Err(Client::map_timeout(e, "stream timed out waiting for frame")),
                        )
                    }
                };
                if filled.is_empty() {
                    if buf.is_empty() {
                        return done(
                            self,
                            Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "connection closed without frame",
                            )),
                        );
                    }
                    return done(
                        self,
                        Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "connection closed mid-frame (partial reply)",
                        )),
                    );
                }
                match filled.iter().position(|&b| b == b'\n') {
                    Some(pos) => {
                        let take = pos + 1;
                        (filled[..take].to_vec(), take, true)
                    }
                    None => (filled.to_vec(), filled.len(), false),
                }
            };
            if buf.len() + chunk.len() > limit {
                return done(
                    self,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("response exceeds byte limit ({limit} bytes)"),
                    )),
                );
            }
            buf.extend_from_slice(&chunk);
            self.reader.consume(take);
            if newline {
                let out = match String::from_utf8(buf) {
                    Ok(s) => s,
                    Err(_) => {
                        return done(
                            self,
                            Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "bad response: reply is not valid UTF-8",
                            )),
                        )
                    }
                };
                return done(self, Ok(out));
            }
        }
    }
}

/// Bounded `req_id` rendering for mismatch diagnostics: numeric ids echo
/// exactly (small, client-comparable); every other JSON shape is described
/// by type (and string length) without echoing server-controlled content, so
/// a hostile `req_id` cannot exfiltrate credentials or flood logs.
fn describe_req_id(v: &Value) -> String {
    if let Some(n) = v.as_u64() {
        return n.to_string();
    }
    if let Some(n) = v.as_i64() {
        return n.to_string();
    }
    if let Some(s) = v.as_str() {
        return format!("string(len {})", s.len());
    }
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(_) => "bool".to_string(),
        Value::Number(_) => "number".to_string(),
        Value::Array(a) => format!("array(len {})", a.len()),
        Value::Object(o) => format!("object(keys {})", o.len()),
        Value::String(_) => "string".to_string(),
    }
}

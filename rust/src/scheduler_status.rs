//! Bounded scheduler run-status reporter: opt-in per-run KV lifecycle records.
//!
//! Problem: worker heartbeat text can say an old `DONE`/`READY` while a
//! scheduler-owned process is currently live, so task state is ambiguous.
//! This module adds explicit per-run records without touching heartbeat text.
//!
//! Design (inbox47/48 authoritative): the round-supervision loop never performs
//! synchronous bus waits. All bus IO runs in one owned reporter thread fed by
//! non-blocking coalesced sends; shutdown is cooperative, bounded, and joined
//! on every path (explicit `shutdown` plus a `Drop` fallback that joins,
//! never detaches). No timeout or cancel path spawns a detached or unjoined
//! helper: every connect, DNS decision, and RPC completes in the calling
//! thread under explicit bounds.
//!
//! Keys are unique per run: `ctx.sched.<task>.<agent>.<run_id>` with finite
//! TTLs (active 60s, terminal 1h). Missing, expired, or stale records mean
//! `unknown`, never proof of process exit. No shared `current-run`
//! last-writer-wins pointer exists: readers list the prefix and inspect each
//! run key. See `docs/NATIVE_SCHEDULER_STATUS.md` for grants and commands.
//!
//! Transports speak the same JSON-lines wire as `crate::wire::Client`
//! (`hello` + `kv_put`) but with observability-appropriate owned bounds: one
//! IP-literal `connect_timeout` dial (1s, no DNS, no thread, no `Client::raw`)
//! plus 1s per-RPC deadlines, instead of the 5s/10s coordination defaults.
//! Hostnames are rejected fast without a DNS lookup (explicit IP-literal
//! restriction, documented in `docs/NATIVE_SCHEDULER_STATUS.md`). Failures are
//! sanitized fixed strings (never tokens, never server-controlled text) and
//! never cancel, duplicate, or block the round.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc::{self, SyncSender},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// KV key prefix for all run-status records.
pub const STATUS_KEY_PREFIX: &str = "ctx.sched.";
/// TTL for Starting/Active refreshes: expiry means the scheduler stopped
/// reporting (died, wedged, or bus down), never proof the child exited.
pub const ACTIVE_TTL_MS: u64 = 60_000;
/// TTL for Terminal records: long enough for post-round inspection, still
/// finite so old runs age out instead of looking current.
pub const TERMINAL_TTL_MS: u64 = 3_600_000;
/// Default interval between Active refreshes during a round.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(15);
/// Per-RPC deadline for status puts (observability, not coordination).
pub const STATUS_RPC_TIMEOUT: Duration = Duration::from_secs(1);
/// Owned TCP dial bound for status connects: one IP-literal
/// `connect_timeout` in the calling thread. No DNS, no helper thread.
pub const STATUS_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Lifecycle phase observed by the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Starting,
    Active,
    Terminal,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Starting => "starting",
            Phase::Active => "active",
            Phase::Terminal => "terminal",
        }
    }
}

/// Exact terminal outcome, recorded only after the real child/cleanup result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
    Timeout,
    Cancelled,
    CleanupFailed,
    InfraError,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Timeout => "timeout",
            Outcome::Cancelled => "cancelled",
            Outcome::CleanupFailed => "cleanup_failed",
            Outcome::InfraError => "infra_error",
        }
    }
}

/// Cleanup certainty: `Clean` only after owned-group + owned-scope cleanup is
/// verified empty; `Uncertain` on any cleanup failure (fail closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cleanup {
    Pending,
    Clean,
    Uncertain,
}

impl Cleanup {
    pub fn as_str(self) -> &'static str {
        match self {
            Cleanup::Pending => "pending",
            Cleanup::Clean => "clean",
            Cleanup::Uncertain => "uncertain",
        }
    }
}

/// The manager state used to prove an owned scope empty. A manager timeout
/// can mean forced cleanup after the round child already exited successfully;
/// it is independent of the scheduler's round timeout and child exit code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeCleanup {
    pub stop_requested: bool,
    pub stop_exit_code: Option<i32>,
    pub load_state: String,
    pub active_state: String,
    pub manager_result: Option<String>,
    pub empty_verified: bool,
}

impl ScopeCleanup {
    fn to_json(&self) -> Value {
        json!({
            "stop_requested": self.stop_requested,
            "stop_exit_code": self.stop_exit_code,
            "load_state": self.load_state,
            "active_state": self.active_state,
            "manager_result": self.manager_result,
            "empty_verified": self.empty_verified,
        })
    }
}

/// Resource verification outcome. `Verified` only after actual cgroup
/// readback matches every requested limit; `Failed` on mismatch/refusal;
/// `Unavailable` when cgroup files cannot be read (wrong platform, missing
/// controller, IO error). Never inferred from command exit codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceVerification {
    Verified,
    Failed,
    Unavailable,
}

impl ResourceVerification {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceVerification::Verified => "verified",
            ResourceVerification::Failed => "failed",
            ResourceVerification::Unavailable => "unavailable",
        }
    }
}

/// Observed cgroup limits read back from the exact round scope. Each field
/// is `Some` only when requested and read exactly into its integer type.
/// `None` means not requested, unlimited (`max`), unreadable, or a CPU
/// percentage that cannot be represented exactly as a u32. Consult the
/// requested policy and aggregate verification state; failure logs retain
/// exact CPU quota/period values. `Some(0)` swap is explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceObservation {
    pub cpu_quota_percent: Option<u32>,
    pub memory_max_bytes: Option<u64>,
    pub memory_swap_max_bytes: Option<u64>,
    pub verification: ResourceVerification,
}

impl ResourceObservation {
    fn to_json(&self) -> Value {
        json!({
            "cpu_quota_percent": self.cpu_quota_percent,
            "memory_max_bytes": self.memory_max_bytes,
            "memory_swap_max_bytes": self.memory_swap_max_bytes,
            "verification": self.verification.as_str(),
        })
    }
}

fn resource_policy_json(policy: &super::ResourcePolicy) -> Value {
    json!({
        "cpu_quota_percent": policy.cpu_quota_percent,
        "memory_max_bytes": policy.memory_max_bytes,
        "memory_swap_max_bytes": policy.memory_swap_max_bytes,
    })
}

/// One typed run-status record. Serializes to the KV value; never contains
/// credentials.
#[derive(Clone, Debug, PartialEq)]
pub struct StatusRecord {
    pub task: String,
    pub run_id: String,
    pub agent: String,
    pub scheduler_pid: u32,
    pub child_pid: Option<u32>,
    pub scope_unit: Option<String>,
    pub phase: Phase,
    pub started_ts: f64,
    pub updated_ts: f64,
    pub elapsed_s: f64,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub outcome: Option<Outcome>,
    pub cleanup: Cleanup,
    pub log_path: String,
    /// Requested limits from config (`None` when no limit requested).
    pub resources_requested: Option<super::ResourcePolicy>,
    /// Observed limits from cgroup readback (`None` when not requested or
    /// not yet observed). Never claims enforcement on failure.
    pub resources_observed: Option<ResourceObservation>,
}

impl StatusRecord {
    /// Add cleanup evidence captured by supervision without another manager
    /// query. None means no final scope proof was available, not empty.
    pub fn to_json_with_scope_cleanup(&self, scope: Option<&ScopeCleanup>) -> Value {
        let mut value = self.to_json();
        value["scope_cleanup"] = scope.map(ScopeCleanup::to_json).unwrap_or(Value::Null);
        value
    }

    /// Add explicit worker task-completion evidence. Process `outcome` and
    /// `cleanup` stay untouched; the task field is self-reported only and
    /// reads as `unknown` when the worker wrote nothing usable.
    pub fn to_json_with_task(
        &self,
        task: &crate::task_report::TaskCompletion,
    ) -> Value {
        let mut value = self.to_json();
        value["task_completion"] = task.to_json();
        value
    }

    /// Add both final scope proof and worker task evidence to a terminal
    /// record. Scope `None` keeps the legacy null shape.
    pub fn to_json_with_scope_and_task(
        &self,
        scope: Option<&ScopeCleanup>,
        task: &crate::task_report::TaskCompletion,
    ) -> Value {
        let mut value = self.to_json_with_scope_cleanup(scope);
        value["task_completion"] = task.to_json();
        value
    }

    pub fn to_json(&self) -> Value {
        json!({
            "task": self.task,
            "run_id": self.run_id,
            "agent": self.agent,
            "scheduler_pid": self.scheduler_pid,
            "child_pid": self.child_pid,
            "scope_unit": self.scope_unit,
            "phase": self.phase.as_str(),
            "started_ts": self.started_ts,
            "updated_ts": self.updated_ts,
            "elapsed_s": self.elapsed_s,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "outcome": self.outcome.map(|o| o.as_str()),
            "cleanup": self.cleanup.as_str(),
            "log_path": self.log_path,
            "resources_requested": self.resources_requested.as_ref().map(resource_policy_json).unwrap_or(Value::Null),
            "resources_observed": self.resources_observed.as_ref().map(ResourceObservation::to_json).unwrap_or(Value::Null),
        })
    }
}

/// Wall-clock seconds since epoch as `f64` (matches wire/KV timebase).
pub fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Keep one key-safe character class for task/agent fragments.
pub fn sanitize_fragment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Unique run identity: scheduler pid + nanos + per-process counter. Unique
/// across rounds even for the same task/agent; no two runs share a key.
pub fn new_run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}-{}", std::process::id(), nanos, n)
}

/// Unique per-run KV key. Returns `Err` on empty task/agent (fail closed).
pub fn status_key(task: &str, agent: &str, run_id: &str) -> Result<String, String> {
    if task.trim().is_empty() || agent.trim().is_empty() || run_id.trim().is_empty() {
        return Err("bus-status requires non-empty task/agent/run".to_string());
    }
    Ok(format!(
        "{}{}.{}.{}",
        STATUS_KEY_PREFIX,
        sanitize_fragment(task),
        sanitize_fragment(agent),
        run_id,
    ))
}

/// Blocking, bounded single-put transport. `cancel` is the reporter shutdown
/// flag: fakes honor it cooperatively so hanging-bus tests prove bounded
/// shutdown; the native transport relies on socket timeouts (1s) and checks
/// the flag before each fresh RPC (dial, hello, kv_put) plus after hello
/// before kv_put, so cancellation during hello starts no mutation.
pub trait StatusTransport: Send + 'static {
    fn put(
        &mut self,
        key: &str,
        value: Value,
        ttl_ms: u64,
        cancel: &AtomicBool,
    ) -> Result<(), String>;
}

/// Native transport over the JSON-lines wire (`hello` + `kv_put`) with
/// observability bounds. Reuses one connection; drops it on transport errors
/// so the next update reconnects. All errors are sanitized fixed strings.
pub struct NativeStatusTransport {
    addr: String,
    agent: String,
    token: String,
    client: Option<crate::wire::Client>,
    rpc_timeout: Duration,
    connect_timeout: Duration,
}

impl NativeStatusTransport {
    pub fn new(addr: &str, agent: &str, token: &str) -> Self {
        Self {
            addr: addr.to_string(),
            agent: agent.to_string(),
            token: token.to_string(),
            client: None,
            rpc_timeout: STATUS_RPC_TIMEOUT,
            connect_timeout: STATUS_CONNECT_TIMEOUT,
        }
    }

    /// Build from the standard native CLI environment. Never echoes values.
    /// The resulting address must be an `IP:port` literal; hostnames fail
    /// fast at the first `put` without a DNS lookup (see `ensure_connected`).
    pub fn from_env() -> Result<Self, String> {
        let host = std::env::var("AGENT_BUS_HOST")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let port = std::env::var("AGENT_BUS_PORT")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "8379".to_string());
        let agent = std::env::var("AGENT_BUS_AGENT").unwrap_or_default();
        let token = std::env::var("AGENT_BUS_TOKEN").unwrap_or_default();
        if agent.trim().is_empty() || token.trim().is_empty() {
            return Err("bus-status needs AGENT_BUS_AGENT/AGENT_BUS_TOKEN".to_string());
        }
        Ok(Self::new(&format!("{host}:{port}"), &agent, &token))
    }

    fn ensure_connected(&mut self, cancel: &AtomicBool) -> Result<(), String> {
        // Every fresh-RPC boundary respects cancellation: a set flag
        // short-circuits even when a connection is already cached, so a
        // cancelled Active never reuses it for a new mutation. Terminal
        // puts use a fresh flag and still reuse.
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        if self.client.is_some() {
            return Ok(());
        }
        // Owned bounded dial: one IP-literal `connect_timeout` in this
        // thread. No `to_socket_addrs` (blocking DNS), no `Client::raw`
        // (5s + DNS), no helper thread on any path. Hostnames are an
        // explicit unsupported-address error, returned without lookup.
        let sock: std::net::SocketAddr = self
            .addr
            .parse()
            .map_err(|_| "unsupported broker address (need IP:port literal)".to_string())?;
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        let stream = std::net::TcpStream::connect_timeout(&sock, self.connect_timeout)
            .map_err(sanitize_io)?;
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        let mut client = crate::wire::Client::from_connected_stream(stream, self.rpc_timeout)
            .map_err(sanitize_io)?;
        let resp = client
            .rpc(&json!({"op": "hello", "agent": self.agent, "token": self.token}))
            .map_err(sanitize_io)?;
        if resp.get("ok") != Some(&json!(true)) {
            return Err("auth refused".to_string());
        }
        // Cancelled during hello must not start a fresh mutation: drop the
        // just-authenticated connection and report cancelled. No kv_put is
        // sent; a later terminal put under its own fresh flag reconnects
        // within its normal fresh bound.
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        self.client = Some(client);
        Ok(())
    }
}

impl StatusTransport for NativeStatusTransport {
    fn put(
        &mut self,
        key: &str,
        value: Value,
        ttl_ms: u64,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        if let Err(e) = self.ensure_connected(cancel) {
            return Err(e);
        }
        // Hello->put boundary: cancellation arriving during connect/hello
        // (or in the race after ensure_connected) must not open a fresh
        // kv_put RPC. The in-flight hello already completed under its 1s
        // bound; this check prevents starting the mutation. A cached
        // connection is kept for a later terminal reuse under a fresh flag.
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        let client = self.client.as_mut().expect("connected");
        let resp = match client.rpc(&json!({
            "op": "kv_put",
            "key": key,
            "value": value,
            "ttl_ms": ttl_ms,
        })) {
            Ok(r) => r,
            Err(e) => {
                self.client = None;
                return Err(sanitize_io(e));
            }
        };
        if resp.get("ok") == Some(&json!(true)) {
            return Ok(());
        }
        let err = resp.get("error").and_then(|v| v.as_str()).unwrap_or("");
        Err(sanitize_server(err))
    }
}

/// Fixed IO diagnosis: kind only, never OS text or addresses.
fn sanitize_io(e: std::io::Error) -> String {
    sanitize_kind(e.kind())
}

fn sanitize_kind(kind: std::io::ErrorKind) -> String {
    use std::io::ErrorKind::*;
    match kind {
        TimedOut | WouldBlock => "timeout".to_string(),
        ConnectionRefused => "connection refused".to_string(),
        ConnectionReset | BrokenPipe | UnexpectedEof => "connection closed".to_string(),
        InvalidData => "protocol error".to_string(),
        PermissionDenied => "auth refused".to_string(),
        InvalidInput => "invalid input".to_string(),
        _ => "transport error".to_string(),
    }
}

/// Fixed server-error diagnosis: category only, never server text.
fn sanitize_server(err: &str) -> String {
    if err.contains("denied") {
        "kv_put denied (grant missing)".to_string()
    } else if err.contains("key required") {
        "key required".to_string()
    } else if err.contains("ttl_ms") {
        "bad ttl".to_string()
    } else if err.contains("auth") {
        "auth refused".to_string()
    } else {
        "kv_put refused".to_string()
    }
}

struct ActiveUpdate {
    key: String,
    value: Value,
    ttl_ms: u64,
}

struct TerminalPut {
    key: String,
    value: Value,
    ttl_ms: u64,
}

/// Reporter outcome for the round log (sanitized, no secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReporterOutcome {
    pub active_ok: usize,
    pub active_failed: usize,
    pub terminal_ok: Option<bool>,
    pub last_error: Option<String>,
}

impl ReporterOutcome {
    fn empty() -> Self {
        Self {
            active_ok: 0,
            active_failed: 0,
            terminal_ok: None,
            last_error: None,
        }
    }

    fn panicked() -> Self {
        Self {
            active_ok: 0,
            active_failed: 0,
            terminal_ok: None,
            last_error: Some("reporter panic".to_string()),
        }
    }
}

/// Owned background reporter: non-blocking coalesced `update`, bounded
/// cooperative `shutdown` that is always joined (explicitly, or via `Drop`).
///
/// Backpressure: at most ONE pending Active snapshot exists (latest wins).
/// Rapid `update` calls overwrite the slot instead of queueing, so a slow bus
/// can never grow memory or delay shutdown with a backlog. The worker is
/// woken via a bounded (cap-1) notify channel; a full notify means "already
/// woken", never a block.
pub struct StatusReporter {
    pending: Arc<Mutex<Option<ActiveUpdate>>>,
    notify_tx: Option<SyncSender<()>>,
    cancel: Arc<AtomicBool>,
    terminal: Arc<Mutex<Option<TerminalPut>>>,
    handle: Option<JoinHandle<ReporterOutcome>>,
}

impl StatusReporter {
    pub fn new(transport: Box<dyn StatusTransport>) -> Self {
        let (notify_tx, notify_rx) = mpsc::sync_channel::<()>(1);
        let pending: Arc<Mutex<Option<ActiveUpdate>>> = Arc::new(Mutex::new(None));
        let cancel = Arc::new(AtomicBool::new(false));
        let terminal: Arc<Mutex<Option<TerminalPut>>> = Arc::new(Mutex::new(None));
        let pending_t = Arc::clone(&pending);
        let cancel_t = Arc::clone(&cancel);
        let terminal_t = Arc::clone(&terminal);
        let handle = std::thread::Builder::new()
            .name("agent-bus-status-reporter".to_string())
            .spawn(move || reporter_loop(transport, notify_rx, &pending_t, &cancel_t, &terminal_t))
            .ok();
        Self {
            pending,
            notify_tx: Some(notify_tx),
            cancel,
            terminal,
            handle,
        }
    }

    /// Queue an Active refresh. Never blocks the supervision loop: the latest
    /// snapshot overwrites any still-pending one (coalesced), and the worker
    /// is woken with a non-blocking notify. Returns false only when the
    /// reporter is gone (observability loss, never a round failure).
    pub fn update(&self, key: &str, value: Value, ttl_ms: u64) -> bool {
        let tx = match &self.notify_tx {
            Some(tx) => tx,
            None => return false,
        };
        let msg = ActiveUpdate {
            key: key.to_string(),
            value,
            ttl_ms,
        };
        match self.pending.lock() {
            Ok(mut slot) => *slot = Some(msg),
            Err(poison) => *poison.into_inner() = Some(msg),
        }
        // Coalesced wake: Full means a wake is already queued and the slot
        // holds the latest; Disconnected means the worker is gone.
        match tx.try_send(()) {
            Ok(()) => true,
            Err(std::sync::mpsc::TrySendError::Full(_)) => true,
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
        }
    }

    /// Bounded cooperative shutdown: abort any in-progress Active, drop the
    /// single pending snapshot (never sent after the terminal), attempt at
    /// most one terminal put with the normal bounded transport, and join the
    /// thread. Worst case is one in-flight Active bound plus one terminal
    /// bound (native: ≤1s in-flight RPC/dial remainder — cancelled hello
    /// starts no kv_put — plus ≤1s dial/≤1s hello/≤1s put fresh, ≤1s put
    /// when already connected; ≤4s fresh total, ≤2s connected); typical
    /// healthy shutdown is <100ms. The shared cancel flag is never cleared:
    /// the terminal put runs under its own fresh flag so aborting actives
    /// cannot open an extra allowance. Terminal outcome/cleanup always
    /// reflect the real round wait/cleanup result computed before shutdown.
    pub fn shutdown(mut self, terminal: Option<(String, Value, u64)>) -> ReporterOutcome {
        self.cancel.store(true, Ordering::Relaxed);
        let put = terminal.map(|(key, value, ttl_ms)| TerminalPut { key, value, ttl_ms });
        match self.terminal.lock() {
            Ok(mut slot) => *slot = put,
            Err(poison) => *poison.into_inner() = put,
        }
        self.notify_tx.take();
        match self.handle.take() {
            Some(h) => h.join().unwrap_or_else(|_| ReporterOutcome::panicked()),
            None => ReporterOutcome::empty(),
        }
    }
}

impl Drop for StatusReporter {
    fn drop(&mut self) {
        if self.handle.is_none() {
            return;
        }
        // Fallback when explicit `shutdown` was skipped (bug path): no
        // terminal put, but still bounded and joined — never detached.
        self.cancel.store(true, Ordering::Relaxed);
        self.notify_tx.take();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn reporter_loop(
    mut transport: Box<dyn StatusTransport>,
    notify_rx: mpsc::Receiver<()>,
    pending: &Mutex<Option<ActiveUpdate>>,
    cancel: &AtomicBool,
    terminal: &Mutex<Option<TerminalPut>>,
) -> ReporterOutcome {
    let mut outcome = ReporterOutcome::empty();
    loop {
        match notify_rx.recv() {
            Ok(()) => {}
            Err(_) => break,
        }
        if cancel.load(Ordering::Relaxed) {
            continue;
        }
        let msg = pending
            .lock()
            .map(|mut g| g.take())
            .unwrap_or_else(|poison| {
                let mut g = poison.into_inner();
                g.take()
            });
        let Some(msg) = msg else { continue };
        if cancel.load(Ordering::Relaxed) {
            continue;
        }
        match transport.put(&msg.key, msg.value, msg.ttl_ms, cancel) {
            Ok(()) => outcome.active_ok += 1,
            Err(e) => {
                outcome.active_failed += 1;
                outcome.last_error = Some(e);
            }
        }
    }
    let term = terminal
        .lock()
        .map(|mut g| g.take())
        .unwrap_or_else(|poison| {
            let mut g = poison.into_inner();
            g.take()
        });
    if let Some(t) = term {
        // Terminal runs under its own fresh flag (never clears the shared
        // abort): actives stay aborted while this one bounded put is
        // attempted with normal transport bounds.
        let terminal_cancel = AtomicBool::new(false);
        match transport.put(&t.key, t.value, t.ttl_ms, &terminal_cancel) {
            Ok(()) => outcome.terminal_ok = Some(true),
            Err(e) => {
                outcome.terminal_ok = Some(false);
                outcome.last_error = Some(e);
            }
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn keys_are_unique_per_run_and_sanitized() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let id = new_run_id();
            let key = status_key("my task!", "ag/ent", &id).unwrap();
            assert!(key.starts_with(STATUS_KEY_PREFIX));
            assert!(key.contains("my-task-"));
            assert!(key.contains("ag-ent"));
            assert!(seen.insert(key));
        }
    }

    #[test]
    fn empty_task_agent_run_rejected() {
        assert!(status_key("", "a", "r").is_err());
        assert!(status_key("t", "", "r").is_err());
        assert!(status_key("t", "a", "").is_err());
    }

    #[test]
    fn record_serializes_typed_fields() {
        let rec = StatusRecord {
            task: "t".into(),
            run_id: "r".into(),
            agent: "a".into(),
            scheduler_pid: 1,
            child_pid: Some(2),
            scope_unit: Some("u.scope".into()),
            phase: Phase::Terminal,
            started_ts: 10.0,
            updated_ts: 12.5,
            elapsed_s: 2.5,
            exit_code: Some(0),
            timed_out: false,
            cancelled: false,
            outcome: Some(Outcome::Success),
            cleanup: Cleanup::Clean,
            log_path: "l".into(),
            resources_requested: None,
            resources_observed: None,
        };
        let v = rec.to_json();
        assert_eq!(v["task"], json!("t"));
        assert_eq!(v["phase"], json!("terminal"));
        assert_eq!(v["outcome"], json!("success"));
        assert_eq!(v["cleanup"], json!("clean"));
        assert_eq!(v["scheduler_pid"], json!(1));
        assert_eq!(v["child_pid"], json!(2));
        assert!(v.get("token").is_none());
        assert_eq!(v["resources_requested"], Value::Null);
        assert_eq!(v["resources_observed"], Value::Null);
    }

    #[test]
    fn record_serializes_requested_vs_observed_resources() {
        let req = super::super::ResourcePolicy {
            cpu_quota_percent: Some(100),
            memory_max_bytes: Some(4294967296),
            memory_swap_max_bytes: Some(0),
        };
        let obs = ResourceObservation {
            cpu_quota_percent: Some(100),
            memory_max_bytes: Some(4294967296),
            memory_swap_max_bytes: Some(0),
            verification: ResourceVerification::Verified,
        };
        let rec = StatusRecord {
            task: "t".into(),
            run_id: "r".into(),
            agent: "a".into(),
            scheduler_pid: 1,
            child_pid: Some(2),
            scope_unit: Some("u.scope".into()),
            phase: Phase::Terminal,
            started_ts: 10.0,
            updated_ts: 12.5,
            elapsed_s: 2.5,
            exit_code: Some(0),
            timed_out: false,
            cancelled: false,
            outcome: Some(Outcome::Success),
            cleanup: Cleanup::Clean,
            log_path: "l".into(),
            resources_requested: Some(req),
            resources_observed: Some(obs),
        };
        let v = rec.to_json();
        assert_eq!(v["resources_requested"]["cpu_quota_percent"], json!(100));
        assert_eq!(
            v["resources_requested"]["memory_max_bytes"],
            json!(4294967296u64)
        );
        assert_eq!(v["resources_requested"]["memory_swap_max_bytes"], json!(0));
        assert_eq!(v["resources_observed"]["memory_swap_max_bytes"], json!(0));
        assert_eq!(v["resources_observed"]["verification"], json!("verified"));
        assert!(v.get("token").is_none());
        // Failed vs unavailable are distinct strings, never silent success.
        for (ver, s) in [
            (ResourceVerification::Failed, "failed"),
            (ResourceVerification::Unavailable, "unavailable"),
        ] {
            let o = ResourceObservation {
                cpu_quota_percent: None,
                memory_max_bytes: None,
                memory_swap_max_bytes: None,
                verification: ver,
            };
            assert_eq!(o.to_json()["verification"], json!(s));
        }
    }
}

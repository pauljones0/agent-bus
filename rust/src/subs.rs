//! Native subscription registry: exact/glob patterns, per-connection
//! ownership, bounded queues, and truthful delivery accounting.
//!
//! Source-backed slice of the transitional `broker.py` subscribe path
//! (text-only contract): `subscribe` (925-973: ACL via `covers`,
//! `sub_id` hex12, per-connection `my_subs`, `from_seq`/`tail` replay
//! with expiry, 5000 cap, exact-topic cursor), `subs` (976-991: admin
//! `"*"` sees all, others see own, `age_s`/`delivered`/`dropped`/
//! `queued`), `unsubscribe` (1008-1013: per-connection isolation,
//! idempotent ok), `deliver`/`try_deliver` (487-515: fnmatch fan-out,
//! shared 2000-queue, oldest-evicted drops), and disconnect cleanup
//! (1531-1532: drop owned subs).
//!
//! Native corrections (each gated by `rust/tests/subscriptions.rs` and
//! noted in `docs/NATIVE_SUBSCRIPTIONS.md`):
//! - Control receipts are never dropped: `subscribe`/`unsubscribe`/
//!   `subs` replies and replay frames are reliable. Live frames evict
//!   only older live frames, never reliable frames. Python's shared
//!   `out_q` could drop a control/replay to make room for live.
//! - Registration/replay/live is atomic: a subscription registers as
//!   pending with a per-topic snapshot, replays only `<= snapshot`
//!   (no duplicates), buffers live committed after the snapshot in a
//!   bounded pending queue during replay, then drains pending after
//!   replay (no gaps, ordered). Python's `await out_q.put` replay can
//!   interleave live before remaining replay.
//! - `from_seq`/`tail` are strictly validated as non-negative integers
//!   (missing means 0); non-integers, negatives-as-floats, bools,
//!   strings, and explicit null are errors with the request id.
//!   Python's `int(... or 0)` coerces/truncates and can drop the
//!   connection without a receipt on garbage.
//! - Malformed bracket patterns fall back to literal-`[` matching
//!   (preserving Python `fnmatch` leniency) instead of failing the
//!   subscribe; grants still use strict [`acl::Pattern`].
//! - Live `msg` omits the redundant `topic` member (matching native
//!   `fetch` messages); `frame.topic` is authoritative. Python stores
//!   `topic` inside `msg` as well.
//!
//! Memory bounds: per-connection outbound queues hold at most
//! [`SUBS_QUEUE_MAX`] frames; per-subscription pending-live buffers
//! hold at most [`SUBS_PENDING_MAX`] frames during replay; replay
//! scans at most [`SUBS_REPLAY_CAP`] messages. Publishers never block
//! on slow subscribers: live enqueue is non-blocking with explicit
//! drop accounting. Reliable enqueue (replay/control) blocks only the
//! owning connection's reader, never publishers or other connections.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Condvar, Mutex,
};

use serde_json::Value;

use crate::acl::{Pattern, Policy};

/// Maximum replayed messages per `subscribe` (matches Python 5000).
pub const SUBS_REPLAY_CAP: usize = 5000;
/// Maximum queued outbound frames per connection (matches Python 2000).
pub const SUBS_QUEUE_MAX: usize = 2000;
/// Maximum pending live frames buffered per subscription while its
/// replay drains. Bounds memory when live posts arrive during a slow
/// replay; overflow drops oldest pending with accounting.
pub const SUBS_PENDING_MAX: usize = 2000;

/// Per-subscription live counters (lock-free so queue eviction never
/// needs the registry lock while holding a queue lock).
#[derive(Debug, Default)]
pub struct SubCounters {
    /// Live frames successfully queued (replay excluded, matching Python).
    pub delivered: AtomicU64,
    /// Live frames evicted/dropped (oldest-evicted + new-dropped).
    pub dropped: AtomicU64,
}

impl SubCounters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::SeqCst)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }
}

/// Pre-parsed subscription matcher: strict [`Pattern`] when valid,
/// else literal-`[` fallback preserving Python `fnmatch` leniency for
/// malformed bracket syntax (unterminated/empty/reversed/overlapping).
#[derive(Clone, Debug)]
pub enum Matcher {
    Parsed(Pattern),
    Fallback(String),
}

impl Matcher {
    pub fn new(pattern: &str) -> Self {
        match Pattern::new(pattern) {
            Ok(p) => Matcher::Parsed(p),
            Err(_) => Matcher::Fallback(pattern.to_string()),
        }
    }

    /// True when `topic` matches the subscription pattern.
    pub fn matches(&self, topic: &str) -> bool {
        match self {
            Matcher::Parsed(p) => p.matches(topic),
            Matcher::Fallback(pat) => fallback_match(topic, pat),
        }
    }
}

/// `*`/`?`/literal matching with `[` always literal (fallback for
/// patterns [`Pattern`] rejects). `*` matches any (possibly empty)
/// char sequence, `?` matches exactly one Unicode scalar, everything
/// else (including `[`, `]`, `!`, `-`, `\`) matches literally.
/// Case-sensitive, iterative with `*` backtracking, over `char`s.
pub fn fallback_match(topic: &str, pattern: &str) -> bool {
    let t: Vec<char> = topic.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let (mut star, mut mark): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// True when `topic` matches subscription `pattern`, using strict
/// [`Pattern`] when valid else [`fallback_match`].
pub fn topic_matches(topic: &str, pattern: &str) -> bool {
    Matcher::new(pattern).matches(topic)
}

/// Generate a unique 12-hex subscription id (matches Python
/// `uuid.hex[:12]` length; uniqueness enforced by the registry).
pub fn gen_sub_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::SeqCst);
    let mut h = DefaultHasher::new();
    (
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        std::process::id(),
        n,
        std::thread::current().id(),
    )
        .hash(&mut h);
    format!("{:012x}", h.finish() & 0xffffffffffff)
}

/// Outbound frame kinds: control receipts (always delivered) vs
/// subscription data (live + replay, delivery-policy enforced at the
/// writer boundary).
///
/// Queue reliability (never dropped for room) still groups control +
/// replay as reliable vs live as droppable, but authorization treats
/// replay as data: auth purges remove live + replay, preserving only
/// control, and the writer checks current policy for both live and
/// replay before sending. Each data frame retains its `sub_id` so the
/// writer can apply current authorization without parsing client-visible
/// JSON.
#[derive(Debug)]
pub enum OutFrame {
    /// `{"req_id":..., ...}` control response (reliable, always delivered).
    Control(Value),
    /// `{"event":"msg",...}` replay frame (reliable for room, data for policy).
    Replay { sub_id: String, frame: Value },
    /// `{"event":"msg",...}` live frame (droppable with accounting, data for policy).
    Live {
        sub_id: String,
        counters: std::sync::Arc<SubCounters>,
        frame: Value,
    },
}

impl OutFrame {
    fn is_live(&self) -> bool {
        matches!(self, OutFrame::Live { .. })
    }

    /// Owning subscription for data frames; `None` for control.
    pub fn sub_id(&self) -> Option<&str> {
        match self {
            OutFrame::Control(_) => None,
            OutFrame::Replay { sub_id, .. } | OutFrame::Live { sub_id, .. } => Some(sub_id),
        }
    }

    pub fn into_value(self) -> Value {
        match self {
            OutFrame::Control(v) | OutFrame::Replay { frame: v, .. } => v,
            OutFrame::Live { frame, .. } => frame,
        }
    }
}

struct OutboxInner {
    queue: VecDeque<OutFrame>,
    closed: bool,
    /// When true, the writer drains remaining reliable frames before
    /// exiting (protocol-error close where the peer is still connected
    /// and must receive the error). When false, the writer discards
    /// (peer gone).
    drain: bool,
}

/// Per-connection bounded outbound queue shared by the connection's
/// reader (reliable control/replay producer), publishers (live
/// producers), and the connection's writer thread (consumer).
///
/// Lock discipline: publishers hold the registry lock while calling
/// [`ConnOutbox::try_push_live`] (registry -> queue order); queue
/// eviction updates only lock-free [`SubCounters`]/`AtomicU64`
/// counters, never the registry, so no queue -> registry path exists.
/// The writer holds only the queue lock. Reliable producers hold no
/// registry lock while waiting.
pub struct ConnOutbox {
    capacity: usize,
    inner: Mutex<OutboxInner>,
    not_empty: Condvar,
    not_full: Condvar,
    hold: Mutex<bool>,
    hold_cv: Condvar,
}

impl ConnOutbox {
    pub fn new(capacity: usize) -> Self {
        ConnOutbox {
            capacity,
            inner: Mutex::new(OutboxInner { queue: VecDeque::new(), closed: false, drain: false }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
            hold: Mutex::new(false),
            hold_cv: Condvar::new(),
        }
    }

    /// Test-only writer hold (deterministic backpressure): while held,
    /// [`ConnOutbox::wait_while_held`] blocks the writer before each pop,
    /// so publishers fill the queue without drain races. Production never
    /// holds. Per-outbox (other connections drain normally).
    pub fn set_hold(&self, hold: bool) {
        *self.hold.lock().unwrap() = hold;
        self.hold_cv.notify_all();
    }

    /// Writer gate: blocks while held, waking on release or close (50ms
    /// timed checks so disconnect during hold still exits). Call before
    /// [`ConnOutbox::pop_for_writer`]; holds no queue lock while waiting.
    pub fn wait_while_held(&self) {
        let mut h = self.hold.lock().unwrap();
        while *h {
            let (new_h, _) = self
                .hold_cv
                .wait_timeout(h, std::time::Duration::from_millis(50))
                .unwrap();
            h = new_h;
            if self.is_closed() {
                break;
            }
        }
    }

    /// Current queued frames (for `subs[].queued`, matching Python
    /// `qsize()` shared-queue semantics).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }

    /// Signal disconnect: the writer exits (discarding unsent frames,
    /// since the peer is gone) and reliable waiters fail.
    pub fn close(&self) {
        let mut g = self.inner.lock().unwrap();
        g.closed = true;
        g.drain = false;
        self.not_empty.notify_all();
        self.not_full.notify_all();
        self.hold_cv.notify_all();
    }

    /// Signal protocol-error close: the writer drains remaining queued
    /// frames (reliable + the terminal error) before exiting, since the
    /// peer is still connected and must receive the error. Callers must
    /// first discard stale live via [`ConnOutbox::retain_reliable`] so
    /// the error is not delayed behind 2000 live frames. No new enqueues
    /// are accepted after close (all fail); the drain terminates because
    /// the closing reader removed its subs first.
    pub fn close_after_drain(&self) {
        let mut g = self.inner.lock().unwrap();
        g.closed = true;
        g.drain = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
        self.hold_cv.notify_all();
    }

    /// Discard queued live frames, preserving reliable (control/replay)
    /// order. Used on protocol-error close to prioritize the terminal
    /// error over stale live. Already-counted deliveries are not
    /// adjusted (deliveries counts enqueued, matching Python).
    pub fn retain_reliable(&self) {
        let mut g = self.inner.lock().unwrap();
        if g.closed {
            return;
        }
        g.queue.retain(|f| !f.is_live());
        // Draining live frees room for the terminal error.
        self.not_full.notify_all();
    }

    /// Auth-boundary purge: discard all queued subscription data
    /// (live + replay), preserving only control receipts in order.
    /// Each purged live counts as dropped (per-sub + global) so
    /// `queued_live = deliveries - drops - drained_live` holds; purged
    /// replay is silent (replays counts queued only, drops stays live-only,
    /// matching the pending-buffer-vanishes convention). Used on
    /// revocation/expiry/identity change where stale data must not cross
    /// the new authentication boundary. Releases any test hold so error
    /// receipts can drain. Name is historical (live = data).
    pub fn purge_live_with_accounting(&self, drops: &AtomicU64) -> usize {
        let mut g = self.inner.lock().unwrap();
        if g.closed {
            return 0;
        }
        let mut kept = VecDeque::with_capacity(g.queue.len());
        let mut purged = 0usize;
        for frame in g.queue.drain(..) {
            match frame {
                OutFrame::Live { counters, .. } => {
                    counters.dropped.fetch_add(1, Ordering::SeqCst);
                    drops.fetch_add(1, Ordering::SeqCst);
                    purged += 1;
                }
                OutFrame::Replay { .. } => {
                    purged += 1;
                }
                other => kept.push_back(other),
            }
        }
        g.queue = kept;
        if purged > 0 {
            self.not_full.notify_all();
        }
        drop(g);
        // Release hold after removal (writer was blocked, cannot have stolen
        // data; now error receipts can drain).
        self.set_hold(false);
        purged
    }

    /// Single-subscription purge: discard queued data (live + replay) for
    /// `sub_id` only, preserving control + other subs' data order.
    /// Purged live counts as dropped; purged replay is silent (see
    /// [`ConnOutbox::purge_live_with_accounting`]). Used when one pattern
    /// loses authorization while siblings stay live.
    pub fn purge_sub_live(&self, sub_id: &str, drops: &AtomicU64) -> usize {
        let mut g = self.inner.lock().unwrap();
        if g.closed {
            return 0;
        }
        let mut kept = VecDeque::with_capacity(g.queue.len());
        let mut purged = 0usize;
        for frame in g.queue.drain(..) {
            match frame {
                OutFrame::Live { sub_id: sid, counters, frame: v } if sid == sub_id => {
                    counters.dropped.fetch_add(1, Ordering::SeqCst);
                    drops.fetch_add(1, Ordering::SeqCst);
                    purged += 1;
                    let _ = v;
                }
                OutFrame::Replay { sub_id: sid, frame: v } if sid == sub_id => {
                    purged += 1;
                    let _ = v;
                }
                other => kept.push_back(other),
            }
        }
        g.queue = kept;
        if purged > 0 {
            self.not_full.notify_all();
        }
        purged
    }

    /// Writer take: waits while empty, returning the typed frame so the
    /// writer can apply current delivery policy to data (live + replay)
    /// while always sending control. On discard-close returns `None`
    /// immediately (discarding any remainder). On drain-close returns
    /// queued frames until empty, then `None`. Notifies one reliable
    /// waiter per pop. Respects the test hold gate (releasing the queue
    /// lock while held so publishers can fill without drain races).
    pub fn pop_for_writer(&self) -> Option<OutFrame> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if g.closed && !g.drain {
                return None;
            }
            if *self.hold.lock().unwrap() {
                drop(g);
                self.wait_while_held();
                g = self.inner.lock().unwrap();
                continue;
            }
            if let Some(frame) = g.queue.pop_front() {
                self.not_full.notify_one();
                return Some(frame);
            }
            if g.closed {
                return None;
            }
            g = self.not_empty.wait(g).unwrap();
        }
    }

    /// Non-blocking live enqueue (publishers only, never waits).
    /// On room: queues and counts delivered. On full with live to
    /// evict: evicts oldest live (counts its drop), queues new (counts
    /// its delivery). On full of reliable only, or closed: drops new
    /// (counts its drop). Returns true when queued.
    pub fn try_push_live(
        &self,
        sub_id: &str,
        counters: &std::sync::Arc<SubCounters>,
        frame: Value,
        deliveries: &AtomicU64,
        drops: &AtomicU64,
    ) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.closed {
            counters.dropped.fetch_add(1, Ordering::SeqCst);
            drops.fetch_add(1, Ordering::SeqCst);
            return false;
        }
        if g.queue.len() < self.capacity {
            g.queue.push_back(OutFrame::Live {
                sub_id: sub_id.to_string(),
                counters: std::sync::Arc::clone(counters),
                frame,
            });
            counters.delivered.fetch_add(1, Ordering::SeqCst);
            deliveries.fetch_add(1, Ordering::SeqCst);
            self.not_empty.notify_one();
            return true;
        }
        // Full: evict oldest live only, never reliable.
        if let Some(idx) = g.queue.iter().position(|f| f.is_live()) {
            if let Some(OutFrame::Live { counters: old_c, .. }) = g.queue.remove(idx) {
                old_c.dropped.fetch_add(1, Ordering::SeqCst);
                drops.fetch_add(1, Ordering::SeqCst);
            }
            g.queue.push_back(OutFrame::Live {
                sub_id: sub_id.to_string(),
                counters: std::sync::Arc::clone(counters),
                frame,
            });
            counters.delivered.fetch_add(1, Ordering::SeqCst);
            deliveries.fetch_add(1, Ordering::SeqCst);
            self.not_empty.notify_one();
            return true;
        }
        // Full of reliable: drop new, count it.
        counters.dropped.fetch_add(1, Ordering::SeqCst);
        drops.fetch_add(1, Ordering::SeqCst);
        false
    }

    /// Reliable control enqueue (reader only): evicts oldest live to
    /// make room when possible (counting the eviction), else waits for
    /// the writer to drain when full of reliable only. Never drops the
    /// control. Fails only on close.
    pub fn push_control(&self, frame: Value, drops: &AtomicU64) -> Result<(), ()> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if g.closed {
                return Err(());
            }
            if g.queue.len() < self.capacity {
                g.queue.push_back(OutFrame::Control(frame));
                self.not_empty.notify_one();
                return Ok(());
            }
            if let Some(idx) = g.queue.iter().position(|f| f.is_live()) {
                if let Some(OutFrame::Live { counters: old_c, .. }) = g.queue.remove(idx) {
                    old_c.dropped.fetch_add(1, Ordering::SeqCst);
                    drops.fetch_add(1, Ordering::SeqCst);
                }
                g.queue.push_back(OutFrame::Control(frame));
                self.not_empty.notify_one();
                return Ok(());
            }
            g = self.not_full.wait(g).unwrap();
        }
    }

    /// Reliable replay enqueue (reader only): waits for room when full,
    /// never evicts (preserving other live), never drops. Retains `sub_id`
    /// so auth purges and the writer delivery check can treat replay as
    /// subscription data. Fails only on close.
    pub fn push_replay(&self, sub_id: &str, frame: Value) -> Result<(), ()> {
        let mut g = self.inner.lock().unwrap();
        loop {
            if g.closed {
                return Err(());
            }
            if g.queue.len() < self.capacity {
                g.queue.push_back(OutFrame::Replay { sub_id: sub_id.to_string(), frame });
                self.not_empty.notify_one();
                return Ok(());
            }
            g = self.not_full.wait(g).unwrap();
        }
    }
}

/// Pending subscription state: per-topic snapshot heads at registration
/// plus the bounded live buffer for posts committed after the snapshot
/// while replay drains.
#[derive(Debug)]
pub struct PendingState {
    /// Topic -> head seq at registration (missing means topic absent,
    /// head 0). Replay includes only `seq <= snapshot`.
    pub snapshot: HashMap<String, u64>,
    /// Clock for expiry filtering (pinned at registration).
    pub now: f64,
    pub from_seq: u64,
    pub tail: usize,
    /// Live committed after the snapshot, in commit order, bounded.
    pub pending: VecDeque<Value>,
}

#[derive(Debug)]
pub enum SubState {
    Pending(PendingState),
    Active,
}

/// One live subscription: pattern, owner, per-connection outbox, and
/// lock-free live counters.
pub struct Subscription {
    pub sub_id: String,
    pub pattern: String,
    pub matcher: Matcher,
    /// Claimed agent name at subscribe time (for non-admin `subs`).
    pub agent: String,
    pub conn_id: u64,
    pub outbox: std::sync::Arc<ConnOutbox>,
    pub created: f64,
    pub counters: std::sync::Arc<SubCounters>,
    pub state: SubState,
}

/// Per-connection authorization snapshot for lifecycle enforcement:
/// hello token + current policy clone. Updated on every revalidation and
/// hello; cleared on auth failure/disconnect. Missing entries deny at
/// production data boundaries ([`SubsRegistry::allows_delivery`] and
/// [`SubsRegistry::deliver_live_with_clock`]): open mode installs an
/// explicit wildcard [`crate::acl::Policy`], never missing state.
/// Direct-registry tests without a policy must use the explicit
/// policy-free [`SubsRegistry::deliver_live`] primitive, not the
/// production predicates. Never wire-visible, never logged.
#[derive(Clone)]
pub struct ConnAuth {
    pub token: String,
    pub policy: Policy,
}

/// Global subscription table: `sub_id` -> [`Subscription`] plus
/// per-connection ownership sets. All methods assume the caller holds
/// the registry mutex; live fan-out holds it across the full enqueue
/// loop (registry -> queue order, non-blocking, bounded).
#[derive(Default)]
pub struct SubsRegistry {
    subs: HashMap<String, Subscription>,
    by_conn: HashMap<u64, HashSet<String>>,
    conn_auth: HashMap<u64, ConnAuth>,
}

impl SubsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.subs.len()
    }

    pub fn contains(&self, sub_id: &str) -> bool {
        self.subs.contains_key(sub_id)
    }

    /// Register a pending subscription (holds no queue locks).
    pub fn register_pending(&mut self, sub: Subscription) {
        self.by_conn.entry(sub.conn_id).or_default().insert(sub.sub_id.clone());
        self.subs.insert(sub.sub_id.clone(), sub);
    }

    pub fn get(&self, sub_id: &str) -> Option<&Subscription> {
        self.subs.get(sub_id)
    }

    pub fn get_mut(&mut self, sub_id: &str) -> Option<&mut Subscription> {
        self.subs.get_mut(sub_id)
    }

    /// Per-connection isolated unsubscribe: removes only when owned by
    /// `conn_id`. Returns true when removed.
    pub fn unsubscribe(&mut self, conn_id: u64, sub_id: &str) -> bool {
        let owned = self.subs.get(sub_id).is_some_and(|s| s.conn_id == conn_id);
        if !owned {
            return false;
        }
        self.subs.remove(sub_id);
        if let Some(set) = self.by_conn.get_mut(&conn_id) {
            set.remove(sub_id);
            if set.is_empty() {
                self.by_conn.remove(&conn_id);
            }
        }
        true
    }

    /// Disconnect cleanup: remove all subscriptions owned by `conn_id`.
    pub fn remove_conn(&mut self, conn_id: u64) -> usize {
        let ids: Vec<String> = self.by_conn.remove(&conn_id).map(|s| s.into_iter().collect()).unwrap_or_default();
        let n = ids.len();
        for id in ids {
            self.subs.remove(&id);
        }
        self.conn_auth.remove(&conn_id);
        n
    }

    /// Install/update the authorization snapshot for `conn_id` (hello and
    /// every successful revalidation). Holds no queue locks.
    pub fn set_conn_auth(&mut self, conn_id: u64, token: &str, policy: &Policy) {
        self.conn_auth.insert(
            conn_id,
            ConnAuth { token: token.to_string(), policy: policy.clone() },
        );
    }

    /// Clear the snapshot for `conn_id` (auth failure). Subs are removed
    /// separately via [`SubsRegistry::remove_conn`]; this only drops auth.
    pub fn clear_conn_auth(&mut self, conn_id: u64) {
        self.conn_auth.remove(&conn_id);
    }

    /// Writer delivery check: current authorization for one data frame.
    /// The writer calls this after preparatory delay/serialization, just
    /// before the first socket write (queue lock released, no locks held
    /// across the write). This call is the admission linearization point:
    /// any policy change committing before it is enforced; a change
    /// committing after it may still deliver this one in-flight frame
    /// (including partial bytes already accepted by the socket, which
    /// cannot be recalled). No immediate delivery-stop barrier is promised.
    /// Denies when the sub is missing/foreign (removed by unsubscribe,
    /// prune, sweep, or disconnect), when no authorization snapshot exists
    /// for `conn_id` (fail closed; open mode installs an explicit wildcard
    /// policy instead), when the snapshot has a finite expiry and `now`
    /// cannot establish validity (non-finite `now`, or finite `now > exp`),
    /// or when the stored pattern lost cover (`!can_subscribe`). Policies
    /// without expiry (`exp: None`, including explicit open) skip only the
    /// expiry step and still enforce existence + cover, even under
    /// non-finite clocks. Control receipts never reach this predicate.
    /// Pure predicate: never removes subs or purges (removal/purge stay
    /// with revalidation/delivery paths under registry -> queue order).
    /// Per-connection ordering could narrow the in-flight window further,
    /// but that is a separate design; global registry/token locks stay out
    /// of blocking socket I/O here.
    pub fn allows_delivery(&self, conn_id: u64, sub_id: &str, now: f64) -> bool {
        let Some(sub) = self.subs.get(sub_id) else {
            return false;
        };
        if sub.conn_id != conn_id {
            return false;
        }
        let Some(auth) = self.conn_auth.get(&conn_id) else {
            return false;
        };
        if auth.policy.exp().is_some() {
            if !now.is_finite() || auth.policy.is_expired(now) {
                return false;
            }
        }
        auth.policy.can_subscribe(&sub.pattern)
    }

    /// Prune owned subs no longer covered by `policy` (narrowed grants),
    /// updating survivors' snapshot to `policy`. Purges queued live for
    /// each pruned `sub_id` via `outbox` (registry -> queue order,
    /// bounded). Returns pruned ids. Missing snapshot installs `policy`
    /// with empty token when the connection still owns subs (explicit
    /// policy, never an allow-without-policy); prunes only denied patterns
    /// (conservative cover check).
    pub fn prune_conn_for_policy(
        &mut self,
        conn_id: u64,
        policy: &Policy,
        outbox: &std::sync::Arc<ConnOutbox>,
        drops: &AtomicU64,
    ) -> Vec<String> {
        let owned: Vec<String> = self
            .by_conn
            .get(&conn_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        let mut pruned = Vec::new();
        for id in owned {
            let Some(sub) = self.subs.get(&id) else { continue };
            if policy.can_subscribe(&sub.pattern) {
                continue;
            }
            pruned.push(id.clone());
        }
        for id in &pruned {
            self.subs.remove(id);
            if let Some(set) = self.by_conn.get_mut(&conn_id) {
                set.remove(id);
            }
            outbox.purge_sub_live(id, drops);
        }
        if self.by_conn.get(&conn_id).is_some_and(|s| s.is_empty()) {
            self.by_conn.remove(&conn_id);
        }
        // Refresh survivors to the current policy (same token, new grants).
        if let Some(auth) = self.conn_auth.get_mut(&conn_id) {
            auth.policy = policy.clone();
        } else if !pruned.is_empty() || self.by_conn.contains_key(&conn_id) {
            self.conn_auth.insert(
                conn_id,
                ConnAuth { token: String::new(), policy: policy.clone() },
            );
        }
        pruned
    }

    /// Revocation sweep: remove all subs on connections whose snapshot
    /// token equals `token`, clearing their snapshots. Returns affected
    /// outboxes (deduped by connection) for caller purge after releasing
    /// the registry lock (no new live can enqueue after removal, so
    /// post-release purge is race-free). Subs without a snapshot have no
    /// token to match and are never swept here; they still deny at the
    /// writer/enqueue boundaries until an explicit policy is installed.
    pub fn remove_token(&mut self, token: &str) -> Vec<std::sync::Arc<ConnOutbox>> {
        let conns: Vec<u64> = self
            .conn_auth
            .iter()
            .filter(|(_, a)| a.token == token)
            .map(|(c, _)| *c)
            .collect();
        let mut outboxes = Vec::new();
        for conn in conns {
            if let Some(ids) = self.by_conn.remove(&conn) {
                // Capture one outbox per connection (shared per-conn).
                if let Some(first) = ids.iter().next() {
                    if let Some(sub) = self.subs.get(first) {
                        outboxes.push(std::sync::Arc::clone(&sub.outbox));
                    }
                }
                for id in ids {
                    self.subs.remove(&id);
                }
            }
            self.conn_auth.remove(&conn);
        }
        outboxes
    }

    /// Snapshot visible subscriptions for `subs`: `(sub_id, pattern,
    /// agent, created, delivered, dropped, queued)`. Admin sees all,
    /// others see only `agent`. `queued` is the shared per-connection
    /// outbox depth (locks each outbox briefly; registry -> queue order).
    pub fn snapshot_visible(
        &self,
        is_admin: bool,
        agent: &str,
    ) -> Vec<(String, String, String, f64, u64, u64, usize)> {
        let mut out = Vec::new();
        for s in self.subs.values() {
            if !is_admin && s.agent != agent {
                continue;
            }
            out.push((
                s.sub_id.clone(),
                s.pattern.clone(),
                s.agent.clone(),
                s.created,
                s.counters.delivered(),
                s.counters.dropped(),
                s.outbox.len(),
            ));
        }
        out
    }

    /// Explicit policy-free fan-out for direct-registry tests (call with
    /// registry + history locks held, in state -> registry order). Active
    /// matches enqueue non-blocking to their outbox; pending matches append
    /// to their bounded pending buffer (overflow drops oldest pending with
    /// accounting). `build_frame` renders the per-sub event frame. No
    /// authorization checks by contract: production wire paths must use
    /// [`SubsRegistry::deliver_live_with_clock`], which denies missing
    /// snapshots and unprovable expiry. Compatibility helper for queue/
    /// registry unit tests only, never a production fallback.
    pub fn deliver_live(
        &mut self,
        topic: &str,
        build_frame: impl Fn(&str) -> Value,
        deliveries: &AtomicU64,
        drops: &AtomicU64,
    ) {
        // Collect matches first (borrow ends before queue ops that need
        // `&mut self` for pending appends vs queue locks for active).
        // To keep registry -> queue order with a single lock hold, we
        // iterate by id and handle each inline.
        let ids: Vec<String> = self
            .subs
            .iter()
            .filter(|(_, s)| s.matcher.matches(topic))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let Some(sub) = self.subs.get_mut(&id) else { continue };
            // Re-check match (pattern cannot change, but keep the guard
            // local so future mutation cannot widen fan-out).
            if !sub.matcher.matches(topic) {
                continue;
            }
            let frame = build_frame(&id);
            match &mut sub.state {
                SubState::Active => {
                    sub.outbox.try_push_live(&id, &sub.counters, frame, deliveries, drops);
                }
                SubState::Pending(p) => {
                    if p.pending.len() >= SUBS_PENDING_MAX {
                        p.pending.pop_front();
                        sub.counters.dropped.fetch_add(1, Ordering::SeqCst);
                        drops.fetch_add(1, Ordering::SeqCst);
                    }
                    p.pending.push_back(frame);
                }
            }
        }
    }

    /// Authenticated fan-out: same enqueue as [`SubsRegistry::deliver_live`]
    /// plus delivery-time authorization against the per-connection snapshot
    /// (same predicate as [`SubsRegistry::allows_delivery` less existence,
    /// which holds here). Denies when no snapshot exists for the owning
    /// connection (fail closed), when the snapshot has a finite expiry and
    /// `now` cannot establish validity (non-finite `now`, or finite
    /// `now > exp`), or when the pattern lost cover (`!can_subscribe`).
    /// Policies without expiry skip only the expiry step and still enforce
    /// cover, even under non-finite clocks. Denied subs are removed
    /// immediately (no delivery, no accounting) and their queued live purged
    /// per-sub (counted drops, control preserved). Holds registry -> queue
    /// order, bounded.
    pub fn deliver_live_with_clock(
        &mut self,
        topic: &str,
        now: f64,
        build_frame: impl Fn(&str) -> Value,
        deliveries: &AtomicU64,
        drops: &AtomicU64,
    ) {
        let ids: Vec<String> = self
            .subs
            .iter()
            .filter(|(_, s)| s.matcher.matches(topic))
            .map(|(id, _)| id.clone())
            .collect();
        let mut denied: Vec<(String, std::sync::Arc<ConnOutbox>)> = Vec::new();
        for id in ids {
            let Some(sub) = self.subs.get_mut(&id) else { continue };
            if !sub.matcher.matches(topic) {
                continue;
            }
            // Delivery-time policy from the snapshot (no token-store lock,
            // so no state -> tokens inversion and no file-IO blocking).
            // Mirrors `allows_delivery`: missing denies, finite-expiry
            // requires finite unexpired `now`, nonexpiring skips expiry.
            let deny = match self.conn_auth.get(&sub.conn_id) {
                None => true,
                Some(auth) => {
                    if auth.policy.exp().is_some() && (!now.is_finite() || auth.policy.is_expired(now)) {
                        true
                    } else {
                        !auth.policy.can_subscribe(&sub.pattern)
                    }
                }
            };
            if deny {
                denied.push((id.clone(), std::sync::Arc::clone(&sub.outbox)));
                continue;
            }
            let frame = build_frame(&id);
            match &mut sub.state {
                SubState::Active => {
                    sub.outbox.try_push_live(&id, &sub.counters, frame, deliveries, drops);
                }
                SubState::Pending(p) => {
                    if p.pending.len() >= SUBS_PENDING_MAX {
                        p.pending.pop_front();
                        sub.counters.dropped.fetch_add(1, Ordering::SeqCst);
                        drops.fetch_add(1, Ordering::SeqCst);
                    }
                    p.pending.push_back(frame);
                }
            }
        }
        for (id, outbox) in denied {
            if let Some(sub) = self.subs.remove(&id) {
                if let Some(set) = self.by_conn.get_mut(&sub.conn_id) {
                    set.remove(&id);
                    if set.is_empty() {
                        self.by_conn.remove(&sub.conn_id);
                    }
                }
            }
            outbox.purge_sub_live(&id, drops);
        }
    }
}

/// One `subs` listing row (broker supplies `age_s`; queue depth is the
/// shared per-connection outbox length, matching Python `qsize()`).
#[derive(Clone, Debug)]
pub struct SubRow {
    pub sub_id: String,
    pub pattern: String,
    pub agent: String,
    pub age_s: f64,
    pub delivered: u64,
    pub dropped: u64,
    pub queued: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_star_question_literal_brackets() {
        assert!(fallback_match("board.build", "board.*"));
        assert!(fallback_match("board.build", "board.?????"));
        assert!(!fallback_match("board.build", "board.????"));
        assert!(fallback_match("a[", "a["));
        assert!(!fallback_match("ab", "a["));
        assert!(fallback_match("aXYZb[", "a*b["));
        assert!(fallback_match("", "*"));
        assert!(!fallback_match("", "?"));
    }

    #[test]
    fn matcher_prefers_strict_then_fallback() {
        let m = Matcher::new("board.*");
        assert!(matches!(m, Matcher::Parsed(_)));
        assert!(m.matches("board.build"));
        let bad = Matcher::new("a[");
        assert!(matches!(bad, Matcher::Fallback(_)));
        assert!(bad.matches("a["));
        assert!(!bad.matches("ab"));
    }

    #[test]
    fn live_evicts_only_live_never_reliable() {
        let outbox = ConnOutbox::new(2);
        let deliveries = AtomicU64::new(0);
        let drops = AtomicU64::new(0);
        let c1 = std::sync::Arc::new(SubCounters::new());
        let c2 = std::sync::Arc::new(SubCounters::new());
        // Fill with reliable: control + replay.
        outbox.push_control(serde_json::json!({"req_id": 1}), &drops).unwrap();
        outbox.push_replay("s1", serde_json::json!({"event": "msg"})).unwrap();
        // Live to full-of-reliable drops new, preserves reliable.
        assert!(!outbox.try_push_live("s2", &c2, serde_json::json!({"n": 2}), &deliveries, &drops));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(c2.dropped(), 1);
        assert_eq!(outbox.len(), 2);
        // Drain one reliable, add live, fill, then live evicts live.
        let v = outbox.pop_for_writer().unwrap().into_value();
        assert_eq!(v["req_id"], serde_json::json!(1));
        assert!(outbox.try_push_live("s1", &c1, serde_json::json!({"n": 1}), &deliveries, &drops));
        assert_eq!(outbox.len(), 2); // replay + live
        assert!(outbox.try_push_live("s2", &c2, serde_json::json!({"n": 3}), &deliveries, &drops));
        // Oldest live (s1) evicted, new live queued, replay preserved.
        assert_eq!(c1.dropped(), 1);
        assert_eq!(c2.delivered(), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(deliveries.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn control_evicts_live_but_replay_waits() {
        let outbox = std::sync::Arc::new(ConnOutbox::new(1));
        let drops = AtomicU64::new(0);
        let c = std::sync::Arc::new(SubCounters::new());
        let deliveries = AtomicU64::new(0);
        assert!(outbox.try_push_live("s", &c, serde_json::json!({"n": 1}), &deliveries, &drops));
        // Control evicts the live immediately.
        outbox.push_control(serde_json::json!({"req_id": 9}), &drops).unwrap();
        assert_eq!(c.dropped(), 1);
        assert_eq!(outbox.len(), 1);
        // Replay to full-of-control would wait; close instead to prove
        // it never evicts (fails on close rather than dropping control).
        outbox.close();
        assert!(outbox.push_replay("s", serde_json::json!({"event": "msg"})).is_err());
    }

    #[test]
    fn auth_purge_drops_live_preserves_reliable_with_accounting() {
        let outbox = ConnOutbox::new(4);
        let deliveries = AtomicU64::new(0);
        let drops = AtomicU64::new(0);
        let c = std::sync::Arc::new(SubCounters::new());
        outbox.push_control(serde_json::json!({"req_id": 1}), &drops).unwrap();
        assert!(outbox.try_push_live("s", &c, serde_json::json!({"n": 1}), &deliveries, &drops));
        assert!(outbox.try_push_live("s", &c, serde_json::json!({"n": 2}), &deliveries, &drops));
        assert_eq!(outbox.len(), 3);
        assert_eq!(outbox.purge_live_with_accounting(&drops), 2);
        assert_eq!(outbox.len(), 1);
        assert_eq!(c.dropped(), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(deliveries.load(Ordering::SeqCst), 2);
        let v = outbox.pop_for_writer().unwrap().into_value();
        assert_eq!(v["req_id"], serde_json::json!(1));
    }

    #[test]
    fn auth_purge_discards_replay_preserving_only_control() {
        let outbox = ConnOutbox::new(5);
        let deliveries = AtomicU64::new(0);
        let drops = AtomicU64::new(0);
        let c = std::sync::Arc::new(SubCounters::new());
        outbox.push_control(serde_json::json!({"req_id": 1}), &drops).unwrap();
        outbox.push_replay("s", serde_json::json!({"event": "msg", "n": 1})).unwrap();
        outbox.push_replay("s", serde_json::json!({"event": "msg", "n": 2})).unwrap();
        assert!(outbox.try_push_live("s", &c, serde_json::json!({"n": 3}), &deliveries, &drops));
        assert_eq!(outbox.len(), 4);
        assert_eq!(outbox.purge_live_with_accounting(&drops), 3);
        assert_eq!(outbox.len(), 1);
        assert_eq!(c.dropped(), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(deliveries.load(Ordering::SeqCst), 1);
        let v = outbox.pop_for_writer().unwrap().into_value();
        assert_eq!(v["req_id"], serde_json::json!(1));
    }

    #[test]
    fn purge_sub_discards_replay_only_for_matching_sub() {
        let outbox = ConnOutbox::new(6);
        let deliveries = AtomicU64::new(0);
        let drops = AtomicU64::new(0);
        let c1 = std::sync::Arc::new(SubCounters::new());
        let c2 = std::sync::Arc::new(SubCounters::new());
        outbox.push_replay("s1", serde_json::json!({"n": 1})).unwrap();
        outbox.push_replay("s2", serde_json::json!({"n": 2})).unwrap();
        assert!(outbox.try_push_live("s1", &c1, serde_json::json!({"n": 3}), &deliveries, &drops));
        assert!(outbox.try_push_live("s2", &c2, serde_json::json!({"n": 4}), &deliveries, &drops));
        assert_eq!(outbox.purge_sub_live("s1", &drops), 2);
        assert_eq!(outbox.len(), 2);
        assert_eq!(c1.dropped(), 1);
        assert_eq!(c2.dropped(), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pop_preserves_typed_data_with_sub_id() {
        let outbox = ConnOutbox::new(3);
        let deliveries = AtomicU64::new(0);
        let drops = AtomicU64::new(0);
        let c = std::sync::Arc::new(SubCounters::new());
        outbox.push_control(serde_json::json!({"req_id": 7}), &drops).unwrap();
        outbox.push_replay("rs1", serde_json::json!({"event": "msg"})).unwrap();
        assert!(outbox.try_push_live("ls2", &c, serde_json::json!({"event": "msg"}), &deliveries, &drops));
        assert!(matches!(outbox.pop_for_writer().unwrap(), OutFrame::Control(_)));
        let f = outbox.pop_for_writer().unwrap();
        assert_eq!(f.sub_id(), Some("rs1"));
        assert!(matches!(f, OutFrame::Replay { .. }));
        let f = outbox.pop_for_writer().unwrap();
        assert_eq!(f.sub_id(), Some("ls2"));
        assert!(matches!(f, OutFrame::Live { .. }));
    }

    #[test]
    fn writer_allows_delivery_enforces_expiry_cover_existence() {
        use std::collections::{HashMap, VecDeque};
        let outbox = std::sync::Arc::new(ConnOutbox::new(4));
        let mut reg = SubsRegistry::new();
        let policy = Policy::from_json(&serde_json::json!({
            "agent": "a", "subscribe": ["board.*"], "exp": 1010.0
        }))
        .unwrap();
        reg.set_conn_auth(9, "tok-a", &policy);
        for (id, pat) in [("s1", "board.build"), ("s2", "board.other")] {
            reg.register_pending(Subscription {
                sub_id: id.into(),
                pattern: pat.into(),
                matcher: Matcher::new(pat),
                agent: "a".into(),
                conn_id: 9,
                outbox: std::sync::Arc::clone(&outbox),
                created: 0.0,
                counters: std::sync::Arc::new(SubCounters::new()),
                state: SubState::Active,
            });
        }
        // Valid finite clock allows; boundary `now == exp` is still live.
        assert!(reg.allows_delivery(9, "s1", 1000.0));
        assert!(reg.allows_delivery(9, "s1", 1010.0));
        // Expired denies.
        assert!(!reg.allows_delivery(9, "s1", 1020.0));
        // Missing/foreign sub denies.
        assert!(!reg.allows_delivery(9, "missing", 1000.0));
        assert!(!reg.allows_delivery(8, "s1", 1000.0));
        // Finite-expiry + non-finite clock denies (cannot prove unexpired).
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(!reg.allows_delivery(9, "s1", bad), "now={bad}");
        }
        // Nonexpiring narrow policy: cover still enforced, clock-free NaN
        // explicitly preserved (no expiry to prove).
        let narrow = Policy::from_json(&serde_json::json!({"agent": "a", "subscribe": ["board.build"]})).unwrap();
        reg.set_conn_auth(9, "tok-a", &narrow);
        assert!(reg.allows_delivery(9, "s1", 1000.0));
        assert!(!reg.allows_delivery(9, "s2", 1000.0));
        assert!(reg.allows_delivery(9, "s1", f64::NAN));
        assert!(reg.allows_delivery(9, "s1", f64::INFINITY));
        // Explicit open/nonexpiring wildcard allows under any clock.
        let open = Policy::from_json(&serde_json::json!({"agent": "a", "subscribe": ["*"]})).unwrap();
        reg.set_conn_auth(9, "tok-a", &open);
        assert!(reg.allows_delivery(9, "s1", 1000.0));
        assert!(reg.allows_delivery(9, "s2", 1000.0));
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(reg.allows_delivery(9, "s1", bad), "open now={bad}");
        }
        // Missing authorization denies at the production boundary, even for
        // otherwise valid clocks/patterns (fail closed, no fixture fallback).
        reg.clear_conn_auth(9);
        assert!(!reg.allows_delivery(9, "s1", 1000.0));
        assert!(!reg.allows_delivery(9, "s1", 1010.0));
        assert!(!reg.allows_delivery(9, "s1", 1020.0));
        assert!(!reg.allows_delivery(9, "s1", f64::NAN));
        // Controls unaffected: control frames carry no sub_id and never reach
        // the predicate; the queue still accepts/delivers them when data denies.
        let drops = AtomicU64::new(0);
        outbox.push_control(serde_json::json!({"req_id": 1}), &drops).unwrap();
        let f = outbox.pop_for_writer().unwrap();
        assert_eq!(f.sub_id(), None);
        assert!(matches!(f, OutFrame::Control(_)));
        let _ = (HashMap::<String, u64>::new(), VecDeque::<Value>::new());
    }

    #[test]
    fn enqueue_denies_missing_expiry_invalid_clock_like_writer() {
        use std::collections::{HashMap, VecDeque};
        let deliveries = AtomicU64::new(0);
        let drops = AtomicU64::new(0);
        // Expiring policy: valid enqueues, boundary allows, expired/invalid
        // denies + prunes, missing denies. Nonexpiring allows under NaN.
        for (name, policy_json, now, expect_queued) in [
            ("valid", serde_json::json!({"agent": "a", "subscribe": ["t"], "exp": 1010.0}), 1000.0, true),
            ("boundary", serde_json::json!({"agent": "a", "subscribe": ["t"], "exp": 1010.0}), 1010.0, true),
            ("expired", serde_json::json!({"agent": "a", "subscribe": ["t"], "exp": 1010.0}), 1020.0, false),
            ("nan-exp", serde_json::json!({"agent": "a", "subscribe": ["t"], "exp": 1010.0}), f64::NAN, false),
            ("inf-exp", serde_json::json!({"agent": "a", "subscribe": ["t"], "exp": 1010.0}), f64::INFINITY, false),
            ("open-nan", serde_json::json!({"agent": "a", "subscribe": ["*"]}), f64::NAN, true),
            ("open-finite", serde_json::json!({"agent": "a", "subscribe": ["*"]}), 1000.0, true),
        ] {
            let outbox = std::sync::Arc::new(ConnOutbox::new(8));
            let mut reg = SubsRegistry::new();
            let policy = Policy::from_json(&policy_json).unwrap();
            reg.set_conn_auth(11, "tok-a", &policy);
            reg.register_pending(Subscription {
                sub_id: "s".into(),
                pattern: "t".into(),
                matcher: Matcher::new("t"),
                agent: "a".into(),
                conn_id: 11,
                outbox: std::sync::Arc::clone(&outbox),
                created: 0.0,
                counters: std::sync::Arc::new(SubCounters::new()),
                state: SubState::Active,
            });
            // Control queued before fan-out must survive deny-purges.
            outbox.push_control(serde_json::json!({"req_id": 1}), &drops).unwrap();
            reg.deliver_live_with_clock("t", now, |id| serde_json::json!({"event": "msg", "sub_id": id}), &deliveries, &drops);
            if expect_queued {
                assert_eq!(outbox.len(), 2, "{name}: control + live");
                assert!(reg.contains("s"), "{name}: survivor kept");
            } else {
                assert_eq!(outbox.len(), 1, "{name}: control only, data purged");
                assert!(!reg.contains("s"), "{name}: denied sub pruned");
                let f = outbox.pop_for_writer().unwrap();
                assert!(matches!(f, OutFrame::Control(_)), "{name}: control preserved");
            }
            let _ = (HashMap::<String, u64>::new(), VecDeque::<Value>::new());
        }
        // Missing snapshot denies at the authenticated enqueue boundary.
        {
            let outbox = std::sync::Arc::new(ConnOutbox::new(8));
            let mut reg = SubsRegistry::new();
            reg.register_pending(Subscription {
                sub_id: "s".into(),
                pattern: "t".into(),
                matcher: Matcher::new("t"),
                agent: "a".into(),
                conn_id: 12,
                outbox: std::sync::Arc::clone(&outbox),
                created: 0.0,
                counters: std::sync::Arc::new(SubCounters::new()),
                state: SubState::Active,
            });
            outbox.push_control(serde_json::json!({"req_id": 1}), &drops).unwrap();
            reg.deliver_live_with_clock("t", 1000.0, |id| serde_json::json!({"event": "msg", "sub_id": id}), &deliveries, &drops);
            assert!(!reg.contains("s"), "missing auth pruned");
            assert_eq!(outbox.len(), 1, "control preserved, live denied");
        }
        // Explicit policy-free primitive still enqueues without a snapshot
        // (compatibility helper for direct-registry queue tests only).
        {
            let outbox = std::sync::Arc::new(ConnOutbox::new(8));
            let mut reg = SubsRegistry::new();
            reg.register_pending(Subscription {
                sub_id: "s".into(),
                pattern: "t".into(),
                matcher: Matcher::new("t"),
                agent: "a".into(),
                conn_id: 13,
                outbox: std::sync::Arc::clone(&outbox),
                created: 0.0,
                counters: std::sync::Arc::new(SubCounters::new()),
                state: SubState::Active,
            });
            reg.deliver_live("t", |id| serde_json::json!({"event": "msg", "sub_id": id}), &deliveries, &drops);
            assert!(reg.contains("s"), "policy-free keeps the sub");
            assert_eq!(outbox.len(), 1, "policy-free enqueues live");
        }
    }

    #[test]
    fn prune_narrowed_pattern_removes_only_denied_with_purge() {
        use std::collections::{HashMap, VecDeque};
        let outbox = std::sync::Arc::new(ConnOutbox::new(10));
        let mut reg = SubsRegistry::new();
        let wide = Policy::from_json(&serde_json::json!({"agent": "a", "subscribe": ["*"]})).unwrap();
        reg.set_conn_auth(7, "tok-a", &wide);
        for (id, pat) in [("s1", "board.build"), ("s2", "other.x")] {
            reg.register_pending(Subscription {
                sub_id: id.into(),
                pattern: pat.into(),
                matcher: Matcher::new(pat),
                agent: "a".into(),
                conn_id: 7,
                outbox: std::sync::Arc::clone(&outbox),
                created: 0.0,
                counters: std::sync::Arc::new(SubCounters::new()),
                state: SubState::Pending(PendingState {
                    snapshot: HashMap::new(),
                    now: 0.0,
                    from_seq: 0,
                    tail: 0,
                    pending: VecDeque::new(),
                }),
            });
            // Activate immediately for the purge path.
            reg.get_mut(id).unwrap().state = SubState::Active;
        }
        let narrow =
            Policy::from_json(&serde_json::json!({"agent": "a", "subscribe": ["board.*"]})).unwrap();
        let drops = AtomicU64::new(0);
        let pruned = reg.prune_conn_for_policy(7, &narrow, &outbox, &drops);
        assert_eq!(pruned, vec!["s2".to_string()]);
        assert!(reg.get("s1").is_some());
        assert!(reg.get("s2").is_none());
    }
}

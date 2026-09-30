//! Pure presence core: authenticated heartbeat liveness and `agents` roster.
//!
//! Source-backed slice of the transitional `broker.py` presence lifecycle
//! (text-only contract, current-tree line numbers):
//! `touch` (806-817: auth-only, retired-suppress, `last_seen`+`addr` refresh,
//! non-string `str` coercion, 200-char truncation), `hello` (834-860: new
//! connections get `"online"` only when absent, otherwise preserve), `ping`
//! (862-865: never touches) + generic `touch()` after auth (867-870:
//! every authenticated op refreshes liveness, even denied/unknown ops),
//! `heartbeat` (1503-1506: missing `status` defaults to `"online"`,
//! explicit null preserves), `agents` (1508-1515: `{status, age_s,
//! online}` with `round(now-last_seen,1)` and `online <= 600`), periodic
//! pruning (548-565: `>86400` drops presence, `>3600` drops retired,
//! leases use absolute `expires_at` only), and `token_claim` retirement
//! (1369-1375: pop + suppress 1h — wire trigger stays an explicit gap).
//!
//! Memory-only, never WAL: the broker never persists presence, so restart
//! drops the roster (matching legacy). No `addr`, token, or grant ever
//! leaves the wire: snapshots expose only `status`/`age_s`/`online`.
//! Presence never renews leases or concludes jobs: claims use absolute
//! expiry, scheduler/process liveness is separate.
//!
//! Native notes (justified, gated by `rust/tests/presence_wire.rs`):
//! pruning is lazy on presence/authenticated ops plus the optional wire
//! maintenance tick/worker for idle cleanup (production 5s, legacy parity;
//! see `docs/NATIVE_EXPIRY_MAINTENANCE.md`); `age_s` uses Python half-even
//! `round(x,1)`; non-string
//! statuses use Python `True`/`False` for bools, number text for numbers,
//! and compact JSON for containers (matching the existing CLI container
//! divergence from Python `repr`); `addr` format is Rust
//! `SocketAddr` text (internal-only, never wire-visible); non-finite
//! clocks fail closed as `"non-finite time"` (matching `acl`/`kv`).

use std::collections::HashMap;

use serde_json::Value;

/// Online threshold seconds: `now - last_seen <= 600` is online.
pub const ONLINE_THRESHOLD_S: f64 = 600.0;
/// Presence retention seconds: `now - last_seen > 86400` prunes.
pub const RETENTION_S: f64 = 86400.0;
/// Retired-newcomer suppression seconds: `now - ts > 3600` prunes.
pub const RETIRED_SUPPRESSION_S: f64 = 3600.0;
/// Max status chars (Unicode scalar, mirrors `status[:200]`).
pub const STATUS_MAX_CHARS: usize = 200;

/// One present agent: heartbeat status, last liveness, internal peer addr.
#[derive(Clone, Debug)]
pub struct Presence {
    pub status: String,
    pub last_seen: f64,
    pub addr: String,
}

/// Pure roster + retired suppression (no IO, no clock reads).
#[derive(Clone, Debug, Default)]
pub struct PresenceStore {
    agents: HashMap<String, Presence>,
    retired: HashMap<String, f64>,
}

impl PresenceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, agent: &str) -> bool {
        self.agents.contains_key(agent)
    }

    pub fn get(&self, agent: &str) -> Option<&Presence> {
        self.agents.get(agent)
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    pub fn is_retired(&self, agent: &str) -> bool {
        self.retired.contains_key(agent)
    }

    /// Suppressed-retired count (for maintenance reporting; `prune` drops
    /// entries with `now - ts > 3600`).
    pub fn retired_len(&self) -> usize {
        self.retired.len()
    }

    /// Record liveness for an authenticated `agent` at finite `now`.
    /// `status`: `None` preserves, `Some(s)` coerces/truncates to 200 chars.
    /// Returns `false` (no-op) for empty names, retired identities, or
    /// non-finite clocks; otherwise updates `last_seen`+`addr` and returns
    /// `true`. Callers keep `heartbeat` `ok` even when suppressed (legacy).
    pub fn touch(&mut self, agent: &str, status: Option<&str>, now: f64, peer: &str) -> bool {
        if agent.is_empty() || self.retired.contains_key(agent) {
            return false;
        }
        if !now.is_finite() {
            return false;
        }
        let entry = self.agents.entry(agent.to_string()).or_insert(Presence {
            status: String::new(),
            last_seen: now,
            addr: peer.to_string(),
        });
        entry.last_seen = now;
        entry.addr = peer.to_string();
        if let Some(s) = status {
            entry.status = truncate_status(s);
        }
        true
    }

    /// Hello reconnect rule: absent agents get `"online"`, present agents
    /// preserve status (both refresh `last_seen`+`addr`). Suppressed for
    /// empty/retired/non-finite exactly like [`PresenceStore::touch`].
    pub fn hello_touch(&mut self, agent: &str, now: f64, peer: &str) -> bool {
        if agent.is_empty() || self.retired.contains_key(agent) {
            return false;
        }
        if !now.is_finite() {
            return false;
        }
        if self.agents.contains_key(agent) {
            self.touch(agent, None, now, peer)
        } else {
            self.touch(agent, Some("online"), now, peer)
        }
    }

    /// Lazy prune (replaces the 5s thread): drops presence with
    /// `now - last_seen > 86400` and retired with `now - ts > 3600`.
    /// Non-finite `now` is a no-op (fail closed, never mass-drop).
    pub fn prune(&mut self, now: f64) {
        if !now.is_finite() {
            return;
        }
        self.agents.retain(|_, p| now - p.last_seen <= RETENTION_S);
        self.retired
            .retain(|_, ts| now - *ts <= RETIRED_SUPPRESSION_S);
    }

    /// Retire a bootstrap identity (future `token_claim` parity): pops
    /// presence and suppresses re-add for 1h. The wire never calls this
    /// (no `token_claim` op); it exists so the suppression rule is tested.
    pub fn retire(&mut self, agent: &str, now: f64) {
        if agent.is_empty() || !now.is_finite() {
            return;
        }
        self.agents.remove(agent);
        self.retired.insert(agent.to_string(), now);
    }

    /// Roster snapshot for `agents`: `{name: {status, age_s, online}}`.
    /// `age_s` is Python half-even `round(now-last_seen,1)`,
    /// `online` is `now-last_seen <= 600`. Returns `None` for non-finite
    /// `now` or an overflowing age (caller maps to `"non-finite time"`).
    /// Never exposes `addr`.
    pub fn agents_snapshot(&self, now: f64) -> Option<Value> {
        if !now.is_finite() {
            return None;
        }
        let mut out = serde_json::Map::new();
        for (name, p) in &self.agents {
            let delta = now - p.last_seen;
            if !delta.is_finite() {
                return None;
            }
            let age_s = round1_py(delta);
            let online = delta <= ONLINE_THRESHOLD_S;
            out.insert(
                name.clone(),
                serde_json::json!({"status": p.status, "age_s": age_s, "online": online}),
            );
        }
        Some(Value::Object(out))
    }
}

/// Truncate to 200 Unicode scalars (mirrors `status[:200]`).
pub fn truncate_status(s: &str) -> String {
    if s.chars().count() <= STATUS_MAX_CHARS {
        return s.to_string();
    }
    s.chars().take(STATUS_MAX_CHARS).collect()
}

/// Coerce a non-null JSON `status` to text (Python `str` shape):
/// strings as-is, bools as `True`/`False`, numbers as number text,
/// containers as compact JSON (documented divergence from Python `repr`,
/// matching the existing CLI container rule). Null is never passed here
/// (wire maps explicit null to preserve); direct calls get `"None"`.
pub fn coerce_status(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => "None".to_string(),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
        }
    }
}

/// Round the original binary value to one decimal place, ties to even.
/// Scaling by ten first can erase which side of a decimal midpoint the
/// input occupies. Native float formatting rounds without that extra step
/// and preserves negative zero. Values at or above 2^52 are already integral.
/// Non-finite inputs pass through; roster callers reject non-finite ages.
pub fn round1_py(x: f64) -> f64 {
    if !x.is_finite() || x.abs() >= 4_503_599_627_370_496.0 {
        return x;
    }
    format!("{x:.1}")
        .parse()
        .expect("finite native decimal formatting is a valid float")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_ties_go_even_on_exact_halves() {
        // Exact binary halves only (inexact decimals like 2.35 shift off-tie
        // in both Python and Rust, so they are not tie tests).
        assert_eq!(round1_py(2.25), 2.2); // 22.5 -> 22 even
        assert_eq!(round1_py(1.25), 1.2); // 12.5 -> 12 even
        assert_eq!(round1_py(1.75), 1.8); // 17.5 -> 18 even
        assert_eq!(round1_py(0.0), 0.0);
        assert_eq!(round1_py(600.0), 600.0);
        assert_eq!(round1_py(600.06), 600.1);
        assert_eq!(round1_py(599.94), 599.9);
    }
}

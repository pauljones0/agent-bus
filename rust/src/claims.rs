//! Broker-enforced atomic resource claims.
//!
//! Reviewed protocol behavior, ported to Rust:
//! - Owner is always the authenticated transport agent (never a payload field).
//! - Exactly one winner under concurrency (check-and-set under a mutex).
//! - Unique lease/fencing token; renew extends expiry, release retires.
//! - Stable idempotency: retrying an acquire key with the same `ttl_ms`
//!   returns the CURRENT live lease state when the key's lease is still
//!   live (a renew may have extended expiry), and a retired error once the
//!   key's lease is gone. A retired key must never mint a new lease, and a
//!   reused key with different `ttl_ms` is rejected.
//! - WAL-first discipline: the record is appended before in-memory commit,
//!   so a store write failure leaves live state untouched.
//! - Fail-closed capacity: receipts are never evicted; new unique keys are
//!   rejected at capacity before any WAL/state change, while retries of
//!   known keys plus renew/release keep working.
//! - Canonical exact resource names only (no wildcards, dot segments, or
//!   empty/repeated separators). Enforcement is cooperative: the broker
//!   serializes holders per canonical string.
//! - Presence/heartbeat never affects leases: only absolute `expires_at`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const CLAIM_TTL_MAX_MS: u64 = 24 * 3600 * 1000;
pub const CLAIM_IDEM_MAX: usize = 10_000;

#[derive(Clone, Debug, PartialEq)]
pub struct Lease {
    pub owner: String,
    pub token: String,
    pub fencing: u64,
    pub acquired_at: f64,
    pub expires_at: f64,
}

/// Compact live-lease projection for listing (no token, no `acquired_at`).
/// Matches legacy `claim_list` shape `{resource, holder, fencing, expires_at}`
/// (`broker.py:1482-1493`, passive text reference). Tokens never appear in
/// listings; callers keep acquire/renew/status receipts for renewal.
#[derive(Clone, Debug, PartialEq)]
pub struct LiveLease {
    pub resource: String,
    pub holder: String,
    pub fencing: u64,
    pub expires_at: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClaimError {
    pub error: String,
    pub conflict: bool,
    pub retired: bool,
    pub expired: bool,
    pub capacity: bool,
    pub holder: Option<String>,
    pub token: Option<String>,
    pub fencing: Option<u64>,
    pub expires_at: Option<f64>,
}

impl ClaimError {
    fn plain(msg: impl Into<String>) -> Self {
        ClaimError {
            error: msg.into(),
            conflict: false,
            retired: false,
            expired: false,
            capacity: false,
            holder: None,
            token: None,
            fencing: None,
            expires_at: None,
        }
    }
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

/// Canonical exact resource names: start alnum, then alnum/`._-`/`/`/`:`,
/// at most 256 chars, no wildcards, no empty/`.`/`..` segments.
pub fn valid_claim_resource(resource: &str) -> bool {
    if resource.is_empty() || resource.len() > 256 {
        return false;
    }
    let mut chars = resource.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    if !resource.chars().all(|c| c.is_ascii_alphanumeric() || "._-/:".contains(c)) {
        return false;
    }
    if resource.contains(['*', '?', '[']) {
        return false;
    }
    if resource.contains('/') {
        if resource.starts_with('/') || resource.ends_with('/') || resource.contains("//") {
            return false;
        }
        for part in resource.split('/') {
            if part.is_empty() || part == "." || part == ".." {
                return false;
            }
            if !part.chars().all(|c| c.is_ascii_alphanumeric() || "._-:".contains(c)) {
                return false;
            }
        }
    } else if resource == "." || resource == ".." {
        return false;
    }
    true
}

#[derive(Clone, Debug)]
struct Receipt {
    token: String,
    fencing: u64,
    acquired_at: f64,
    expires_at: f64,
    ttl_ms: u64,
}

/// Point-in-time claim state for canonical WAL compaction.
///
/// Compaction regenerates one `claim_acquire` per receipt (bounded by the
/// fail-closed idempotency bound, never the full record history), plus a
/// `claim_release` for receipts whose lease is gone so replay restores the
/// retired state instead of resurrecting the lease, plus releases carrying
/// fencing-only resources. Live idem-less leases are included so no live
/// holder is dropped.
#[derive(Clone, Debug, Default)]
pub struct ClaimSnapshot {
    /// (owner, resource, idem_key, token, fencing, acquired_at, expires_at, ttl_ms)
    pub receipts: Vec<(String, String, String, String, u64, f64, f64, u64)>,
    /// Live leases after purging expiry at the snapshot time: (resource, lease).
    pub live: Vec<(String, Lease)>,
    /// Highest fencing counter per resource.
    pub fencing: Vec<(String, u64)>,
}

/// Append-ahead log sink. `append` runs BEFORE any in-memory commit; an
/// `Err` aborts the operation with state untouched (WAL-first discipline).
/// Grant records must be fsync-backed before ack by the caller.
pub trait ClaimWal {
    fn append(&mut self, rec: WalClaim) -> Result<(), String>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum WalClaim {
    Acquire {
        resource: String,
        owner: String,
        token: String,
        fencing: u64,
        acquired_at: f64,
        expires_at: f64,
        idem: Option<String>,
        ttl_ms: Option<u64>,
        renew: bool,
    },
    Release { resource: String, fencing: u64 },
}

#[derive(Debug, Default)]
struct Inner {
    leases: HashMap<String, Lease>,
    fencing: HashMap<String, u64>,
    idem: HashMap<(String, String, String), Receipt>,
    next_token: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ClaimStore {
    inner: Arc<Mutex<Inner>>,
    idem_max: usize,
}

impl ClaimStore {
    pub fn new() -> Self {
        ClaimStore { inner: Arc::new(Mutex::new(Inner::default())), idem_max: CLAIM_IDEM_MAX }
    }

    /// Test hook for the fail-closed capacity regression.
    pub fn with_capacity(idem_max: usize) -> Self {
        ClaimStore { inner: Arc::new(Mutex::new(Inner::default())), idem_max }
    }

    fn live_inner(inner: &Inner, resource: &str, now: f64) -> Option<Lease> {
        inner.leases.get(resource).filter(|l| now < l.expires_at).cloned()
    }

    fn purge_expired(inner: &mut Inner, now: f64) {
        inner.leases.retain(|_, l| now < l.expires_at);
    }

    /// Replay a WAL record (compaction/restart path). Never fails closed on
    /// capacity: replay restores every receipt.
    pub fn apply(&self, rec: &WalClaim) {
        let mut inner = self.inner.lock().unwrap();
        match rec {
            WalClaim::Acquire { resource, owner, token, fencing, acquired_at, expires_at, idem, ttl_ms, .. } => {
                let f = inner.fencing.get(resource).copied().unwrap_or(0);
                inner.fencing.insert(resource.clone(), f.max(*fencing));
                let cur = inner.leases.get(resource);
                if cur.is_none() || cur.is_some_and(|c| *fencing >= c.fencing) {
                    inner.leases.insert(
                        resource.clone(),
                        Lease {
                            owner: owner.clone(),
                            token: token.clone(),
                            fencing: *fencing,
                            acquired_at: *acquired_at,
                            expires_at: *expires_at,
                        },
                    );
                }
                if let Some(key) = idem {
                    inner.idem.insert(
                        (owner.clone(), resource.clone(), key.clone()),
                        Receipt {
                            token: token.clone(),
                            fencing: *fencing,
                            acquired_at: *acquired_at,
                            expires_at: *expires_at,
                            ttl_ms: ttl_ms.unwrap_or(0),
                        },
                    );
                }
            }
            WalClaim::Release { resource, fencing } => {
                let f = inner.fencing.get(resource).copied().unwrap_or(0);
                inner.fencing.insert(resource.clone(), f.max(*fencing));
                if let Some(cur) = inner.leases.get(resource) {
                    if cur.fencing <= *fencing {
                        inner.leases.remove(resource);
                    }
                }
            }
        }
    }

    pub fn acquire(
        &self,
        wal: &mut impl ClaimWal,
        agent: &str,
        resource: &str,
        ttl_ms: u64,
        idem_key: Option<&str>,
        now: f64,
    ) -> Result<Lease, ClaimError> {
        if !valid_claim_resource(resource) {
            return Err(ClaimError::plain(format!("invalid resource: {resource:?}")));
        }
        if ttl_ms == 0 || ttl_ms > CLAIM_TTL_MAX_MS {
            return Err(ClaimError::plain(format!(
                "ttl_ms must be an integer in [1, {CLAIM_TTL_MAX_MS}]"
            )));
        }
        if let Some(k) = idem_key {
            if k.is_empty() || k.len() > 256 {
                return Err(ClaimError::plain("invalid idempotency_key"));
            }
        }
        let mut inner = self.inner.lock().unwrap();
        Self::purge_expired(&mut inner, now);
        if let Some(k) = idem_key {
            if let Some(prior) = inner.idem.get(&(agent.to_string(), resource.to_string(), k.to_string())).cloned() {
                if prior.ttl_ms != ttl_ms {
                    return Err(ClaimError {
                        error: "idempotency key reused with different ttl_ms; use a fresh key".into(),
                        retired: true,
                        ..ClaimError::plain("")
                    });
                }
                if let Some(live) = Self::live_inner(&inner, resource, now) {
                    if live.token == prior.token {
                        // Same lease still live: report CURRENT state, not the
                        // original receipt (a renew may have extended expiry).
                        return Ok(live);
                    }
                }
                // Key's lease is gone: retired, must never mint a new lease.
                let cur = inner.leases.get(resource).cloned();
                return Err(ClaimError {
                    error: "idempotency key retired; use a fresh key for a new lease".into(),
                    retired: true,
                    holder: cur.as_ref().map(|c| c.owner.clone()),
                    token: Some(prior.token),
                    fencing: Some(prior.fencing),
                    expires_at: cur.map(|c| c.expires_at),
                    ..ClaimError::plain("")
                });
            }
        }
        if let Some(live) = Self::live_inner(&inner, resource, now) {
            return Err(ClaimError {
                error: if live.owner == agent {
                    "already held by this owner".into()
                } else {
                    format!("held by {}", live.owner)
                },
                conflict: true,
                holder: Some(live.owner),
                token: Some(live.token),
                fencing: Some(live.fencing),
                expires_at: Some(live.expires_at),
                ..ClaimError::plain("")
            });
        }
        if let Some(k) = idem_key {
            let key = (agent.to_string(), resource.to_string(), k.to_string());
            if !inner.idem.contains_key(&key) && inner.idem.len() >= self.idem_max {
                return Err(ClaimError {
                    error: "idempotency store at capacity; retry the same key later or contact the operator to raise the bound (receipts are never evicted)".into(),
                    capacity: true,
                    ..ClaimError::plain("")
                });
            }
        }
        let fencing = inner.fencing.get(resource).copied().unwrap_or(0) + 1;
        inner.next_token += 1;
        let token = format!("{:016x}{:016x}", fencing, inner.next_token);
        let expires_at = now + ttl_ms as f64 / 1000.0;
        let rec = WalClaim::Acquire {
            resource: resource.into(),
            owner: agent.into(),
            token: token.clone(),
            fencing,
            acquired_at: now,
            expires_at,
            idem: idem_key.map(str::to_string),
            ttl_ms: Some(ttl_ms),
            renew: false,
        };
        // WAL first: a store failure leaves live state untouched.
        wal.append(rec.clone()).map_err(|e| ClaimError::plain(format!("claim store write failed: {e}")))?;
        inner.fencing.insert(resource.to_string(), fencing);
        let lease = Lease { owner: agent.into(), token: token.clone(), fencing, acquired_at: now, expires_at };
        inner.leases.insert(resource.to_string(), lease.clone());
        if let Some(k) = idem_key {
            inner.idem.insert(
                (agent.to_string(), resource.to_string(), k.to_string()),
                Receipt { token, fencing, acquired_at: now, expires_at, ttl_ms },
            );
        }
        Ok(lease)
    }

    pub fn renew(
        &self,
        wal: &mut impl ClaimWal,
        agent: &str,
        resource: &str,
        token: &str,
        ttl_ms: u64,
        now: f64,
    ) -> Result<Lease, ClaimError> {
        if !valid_claim_resource(resource) {
            return Err(ClaimError::plain(format!("invalid resource: {resource:?}")));
        }
        if ttl_ms == 0 || ttl_ms > CLAIM_TTL_MAX_MS {
            return Err(ClaimError::plain(format!(
                "ttl_ms must be an integer in [1, {CLAIM_TTL_MAX_MS}]"
            )));
        }
        let mut inner = self.inner.lock().unwrap();
        Self::purge_expired(&mut inner, now);
        let live = match inner.leases.get(resource).cloned() {
            Some(l) => l,
            None => {
                return Err(ClaimError {
                    error: "no live lease".into(),
                    expired: true,
                    ..ClaimError::plain("")
                });
            }
        };
        if live.owner != agent || live.token != token {
            return Err(ClaimError {
                error: format!("held by {}", live.owner),
                conflict: true,
                holder: Some(live.owner),
                token: Some(live.token),
                fencing: Some(live.fencing),
                expires_at: Some(live.expires_at),
                ..ClaimError::plain("")
            });
        }
        let new_expiry = now + ttl_ms as f64 / 1000.0;
        wal.append(WalClaim::Acquire {
            resource: resource.into(),
            owner: agent.into(),
            token: live.token.clone(),
            fencing: live.fencing,
            acquired_at: live.acquired_at,
            expires_at: new_expiry,
            idem: None,
            ttl_ms: None,
            renew: true,
        })
        .map_err(|e| ClaimError::plain(format!("claim store write failed: {e}")))?;
        let updated = Lease { expires_at: new_expiry, ..live };
        inner.leases.insert(resource.to_string(), updated.clone());
        Ok(updated)
    }

    pub fn release(&self, wal: &mut impl ClaimWal, agent: &str, resource: &str, token: &str) -> Result<bool, ClaimError> {
        if !valid_claim_resource(resource) {
            return Err(ClaimError::plain(format!("invalid resource: {resource:?}")));
        }
        let mut inner = self.inner.lock().unwrap();
        let live = match inner.leases.get(resource).cloned() {
            Some(l) => l,
            None => return Ok(false),
        };
        if live.owner != agent || live.token != token {
            return Err(ClaimError {
                error: format!("held by {}", live.owner),
                conflict: true,
                holder: Some(live.owner),
                token: Some(live.token),
                fencing: Some(live.fencing),
                expires_at: Some(live.expires_at),
                ..ClaimError::plain("")
            });
        }
        wal.append(WalClaim::Release { resource: resource.into(), fencing: live.fencing })
            .map_err(|e| ClaimError::plain(format!("claim store write failed: {e}")))?;
        inner.leases.remove(resource);
        Ok(true)
    }

    /// Canonical snapshot for WAL compaction. Purges expired leases at `now`
    /// first, so the compacted WAL restores exactly this state on replay.
    /// Receipt count stays within the fail-closed idempotency bound.
    pub fn snapshot(&self, now: f64) -> ClaimSnapshot {
        let mut inner = self.inner.lock().unwrap();
        Self::purge_expired(&mut inner, now);
        let mut receipts: Vec<_> = inner
            .idem
            .iter()
            .map(|((owner, resource, key), r)| {
                (
                    owner.clone(),
                    resource.clone(),
                    key.clone(),
                    r.token.clone(),
                    r.fencing,
                    r.acquired_at,
                    r.expires_at,
                    r.ttl_ms,
                )
            })
            .collect();
        receipts.sort_by(|a, b| {
            (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2))
        });
        let mut live: Vec<_> =
            inner.leases.iter().map(|(r, l)| (r.clone(), l.clone())).collect();
        live.sort_by(|a, b| a.0.cmp(&b.0));
        let mut fencing: Vec<_> =
            inner.fencing.iter().map(|(r, f)| (r.clone(), *f)).collect();
        fencing.sort_by(|a, b| a.0.cmp(&b.0));
        ClaimSnapshot { receipts, live, fencing }
    }

    pub fn status(&self, resource: &str, now: f64) -> Option<Lease> {
        let mut inner = self.inner.lock().unwrap();
        Self::purge_expired(&mut inner, now);
        inner.leases.get(resource).cloned()
    }

    /// Read-only live lease listing at one sampled `now`.
    ///
    /// Uses the existing expiration rule (`now < expires_at` live, matching
    /// `live_inner`/`purge_expired` and legacy `now >= expires_at` expired).
    /// Sorted by resource; excludes released (absent) and expired entries.
    /// No WAL writes, no purge, no full-state snapshot: iterates the live map
    /// once and projects compact `{resource, holder, fencing, expires_at}`
    /// rows without tokens. Non-finite `now` returns empty (fail closed,
    /// never mass-drop, never leak expired rows). The wire layer samples one
    /// finite clock and passes it here, so all rows share that instant.
    pub fn list_live(&self, now: f64) -> Vec<LiveLease> {
        if !now.is_finite() {
            return Vec::new();
        }
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<LiveLease> = inner
            .leases
            .iter()
            .filter(|(_, l)| now < l.expires_at)
            .map(|(r, l)| LiveLease {
                resource: r.clone(),
                holder: l.owner.clone(),
                fencing: l.fencing,
                expires_at: l.expires_at,
            })
            .collect();
        out.sort_by(|a, b| a.resource.cmp(&b.resource));
        out
    }

    pub fn idem_len(&self) -> usize {
        self.inner.lock().unwrap().idem.len()
    }

    /// Drop expired leases at `now` (`now >= expires_at` expired, matching
    /// `live_inner`/`purge_expired` and legacy `now >= expires_at`); returns
    /// the number removed. Idempotency receipts are never evicted (fail-closed
    /// bound preserved). No WAL IO: expiry releases memory only, never writes
    /// a release record (matching legacy `leases.pop` without WAL). Non-finite
    /// `now` is a no-op returning 0 (fail closed, never mass-drop). Used by
    /// the wire maintenance tick for idle cleanup; request paths already purge
    /// via `acquire`/`renew`/`status`/`snapshot`.
    pub fn purge_expired_at(&self, now: f64) -> usize {
        if !now.is_finite() {
            return 0;
        }
        let mut inner = self.inner.lock().unwrap();
        let before = inner.leases.len();
        Self::purge_expired(&mut inner, now);
        before - inner.leases.len()
    }

    /// Stored lease count including expired-but-not-yet-purged (no mutation).
    /// Test introspection: `stored_len` drops after the maintenance tick while
    /// live leases stay.
    pub fn stored_len(&self) -> usize {
        self.inner.lock().unwrap().leases.len()
    }

    /// Live lease count at `now` (`now < expires_at` live, non-mutating filter
    /// matching `live_inner`; never purges, unlike `status`). Non-finite `now`
    /// counts stored (fail closed, no mass-drop decision). Test introspection.
    pub fn live_len_at(&self, now: f64) -> usize {
        let inner = self.inner.lock().unwrap();
        if !now.is_finite() {
            return inner.leases.len();
        }
        inner.leases.values().filter(|l| now < l.expires_at).count()
    }
}

/// In-memory WAL sink for unit tests; set `fail_next` to simulate a store
/// write failure and prove state is untouched.
#[derive(Default)]
pub struct VecWal {
    pub records: Vec<WalClaim>,
    pub fail_next: bool,
}

impl ClaimWal for VecWal {
    fn append(&mut self, rec: WalClaim) -> Result<(), String> {
        if self.fail_next {
            self.fail_next = false;
            return Err("simulated wal_append OSError".into());
        }
        self.records.push(rec);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (ClaimStore, VecWal) {
        (ClaimStore::new(), VecWal::default())
    }

    #[test]
    fn single_winner_and_conflict_details() {
        let (s, mut w) = store();
        let a = s.acquire(&mut w, "alice", "repo/a.rs", 10_000, Some("k1"), 100.0).unwrap();
        let err = s.acquire(&mut w, "bob", "repo/a.rs", 10_000, Some("k2"), 100.5).unwrap_err();
        assert!(err.conflict);
        assert_eq!(err.holder.as_deref(), Some("alice"));
        assert_eq!(err.token.as_deref(), Some(a.token.as_str()));
        assert_eq!(err.fencing, Some(a.fencing));
    }

    #[test]
    fn retry_same_key_returns_current_state_after_renew() {
        let (s, mut w) = store();
        let _ = s.acquire(&mut w, "alice", "repo/b.rs", 10_000, Some("k"), 100.0).unwrap();
        let renewed = s.renew(&mut w, "alice", "repo/b.rs", &s.status("repo/b.rs", 100.5).unwrap().token, 20_000, 101.0).unwrap();
        // Original receipt expiry (110.0) has passed but the live lease runs
        // to 121.0: retry must report CURRENT state, not the old receipt.
        let dup = s.acquire(&mut w, "alice", "repo/b.rs", 10_000, Some("k"), 112.0).unwrap();
        assert_eq!(dup.expires_at, renewed.expires_at);
    }

    #[test]
    fn retry_after_release_is_retired_never_mints() {
        let (s, mut w) = store();
        let lease = s.acquire(&mut w, "alice", "repo/c.rs", 10_000, Some("k"), 100.0).unwrap();
        assert!(s.release(&mut w, "alice", "repo/c.rs", &lease.token).unwrap());
        let err = s.acquire(&mut w, "alice", "repo/c.rs", 10_000, Some("k"), 101.0).unwrap_err();
        assert!(err.retired);
        assert!(s.status("repo/c.rs", 101.0).is_none());
    }

    #[test]
    fn same_key_with_changed_ttl_is_rejected() {
        let (s, mut w) = store();
        let _ = s.acquire(&mut w, "alice", "repo/d.rs", 10_000, Some("k"), 100.0).unwrap();
        let err = s.acquire(&mut w, "alice", "repo/d.rs", 20_000, Some("k"), 100.5).unwrap_err();
        assert!(err.retired);
    }

    #[test]
    fn wal_failure_leaves_state_untouched() {
        let (s, mut w) = store();
        w.fail_next = true;
        assert!(s.acquire(&mut w, "alice", "repo/e.rs", 10_000, Some("k"), 100.0).is_err());
        assert!(s.status("repo/e.rs", 100.0).is_none());
        assert_eq!(s.idem_len(), 0);
        // Renew failure path.
        let lease = s.acquire(&mut w, "alice", "repo/e.rs", 10_000, None, 100.0).unwrap();
        w.fail_next = true;
        assert!(s.renew(&mut w, "alice", "repo/e.rs", &lease.token, 20_000, 101.0).is_err());
        assert_eq!(s.status("repo/e.rs", 101.0).unwrap().expires_at, lease.expires_at);
    }

    #[test]
    fn fail_closed_capacity_rejects_new_keys_keeps_retries() {
        let s = ClaimStore::with_capacity(2);
        let mut w = VecWal::default();
        let _ = s.acquire(&mut w, "a", "repo/1.rs", 60_000, Some("k1"), 1.0).unwrap();
        let l2 = s.acquire(&mut w, "a", "repo/2.rs", 60_000, Some("k2"), 1.0).unwrap();
        // At capacity: a NEW unique key fails before any WAL/state change.
        let before = w.records.len();
        let err = s.acquire(&mut w, "a", "repo/3.rs", 60_000, Some("k3"), 1.0).unwrap_err();
        assert!(err.capacity);
        assert_eq!(w.records.len(), before);
        assert!(s.status("repo/3.rs", 1.0).is_none());
        // Retries of known keys, renew and release still work.
        assert!(s.acquire(&mut w, "a", "repo/1.rs", 60_000, Some("k1"), 2.0).is_ok());
        assert!(s.renew(&mut w, "a", "repo/2.rs", &l2.token, 60_000, 2.0).is_ok());
        assert!(s.release(&mut w, "a", "repo/2.rs", &l2.token).is_ok());
        // A released key stays retired even at capacity: never mints anew.
        let err = s.acquire(&mut w, "a", "repo/2.rs", 60_000, Some("k2"), 3.0).unwrap_err();
        assert!(err.retired);
        assert!(s.status("repo/2.rs", 3.0).is_none());
    }

    #[test]
    fn fencing_is_monotonic_across_release_and_expiry() {
        let (s, mut w) = store();
        let l1 = s.acquire(&mut w, "alice", "repo/f.rs", 10_000, None, 100.0).unwrap();
        assert!(s.release(&mut w, "alice", "repo/f.rs", &l1.token).unwrap());
        let l2 = s.acquire(&mut w, "bob", "repo/f.rs", 10_000, None, 101.0).unwrap();
        assert!(l2.fencing > l1.fencing);
        // Expiry path: lease lapses at 111.0, next acquire keeps climbing.
        let l3 = s.acquire(&mut w, "carol", "repo/f.rs", 10_000, None, 200.0).unwrap();
        assert!(l3.fencing > l2.fencing);
    }

    #[test]
    fn canonical_resource_validation() {
        assert!(valid_claim_resource("repo/a.rs"));
        assert!(valid_claim_resource("a"));
        assert!(valid_claim_resource("ns:res-1/x.y_z"));
        for bad in ["", "a//b", "/a", "a/", "a/./b", "../x", ".", "..", "a b", "a*b", "*"] {
            assert!(!valid_claim_resource(bad), "{bad} should be invalid");
        }
    }

    #[test]
    fn presence_never_expires_leases_only_absolute_time() {
        let (s, mut w) = store();
        let _ = s.acquire(&mut w, "alice", "repo/g.rs", 10_000, None, 100.0).unwrap();
        // Long after any heartbeat would go stale, the lease is still live.
        assert!(s.status("repo/g.rs", 109.9).is_some());
        assert!(s.status("repo/g.rs", 110.0).is_none());
    }
}

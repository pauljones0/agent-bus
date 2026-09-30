//! Pure KV state/record core: validate-before-durability, mutate-after.
//!
//! Native port of the transitional Python broker's KV contract (`broker.py`
//! `kv_store`/`kv_exp`, read as text only), without any wire, ACL, or
//! presence integration. Record shapes are preserved semantically (see
//! `docs/NATIVE_KV_MIGRATION.md`; Unicode escaping and object key order
//! may differ from the legacy writer, so byte equality is not claimed):
//! - put: `{"t":"kv","key":..,"value":..,"exp":..}`
//! - delete: `{"t":"kv_del","key":..}`
//! - snapshot: `{"v":1,"kv":{..},"exp":{..}}` (live keys only)
//!
//! Durability discipline (inverts the legacy order, which mutated memory
//! before the WAL append): every mutation is `prepare_*` (validate +
//! render the canonical record line) and then `commit_*`, which invokes
//! the caller-injected durability callback FIRST and applies the
//! in-memory change only after it succeeds. A failed callback leaves
//! live state untouched. The future broker wires the callback to its
//! WAL append + fsync; this module performs no IO.
//!
//! Time is always caller-provided (`now` unix seconds as `f64`) so expiry
//! and replay are deterministic. A key is expired exactly when
//! `now > exp`; at `now == exp` it is still live, matching legacy
//! `kv_expired` and the replay/compaction `< now` skip boundary.
//! All `now` and stored `exp` values must be finite: `prepare_put`
//! rejects non-finite times before any durability work, and every read
//! API documents the same finite-`now` precondition. This avoids the
//! serde divergence where non-finite `f64` serializes as JSON null
//! while memory retains the non-finite value.
//!
//! Intentional legacy corrections (see `docs/NATIVE_KV_MIGRATION.md`):
//! - Replay treats an already-expired put as a tombstone that suppresses
//!   older state instead of skipping it, so a superseded value can never
//!   resurrect. Legacy `continue` left the older value live.
//! - Delete reports `found` by key presence, so deleting a JSON-null
//!   value reports `found=true`. Legacy `pop(...) is not None` reported
//!   `false` for null values.
//! - Structurally invalid records are skipped and counted. Legacy skipped
//!   only JSON-decode failures; a parsed record with a missing/wrongly
//!   typed field raised out of replay.
//! - Non-finite write times are rejected. Legacy could store NaN/Inf
//!   expiries (Python `time.time() + ttl/1000` with a non-finite `ttl`);
//!   native returns `KvError::NonFiniteTime` before durability.
//! - Snapshot restore fails atomically on a malformed `exp` entry for a
//!   stored key instead of dropping the TTL and making corrupt data
//!   immortal. Legacy blindly updated `kv_exp` (or crashed on read).
//! - Snapshot documents carrying any top-level `v` member must be
//!   version 1; unsupported versions fail instead of loading `v`/`kv`/
//!   `exp` metadata as flat keys. Legacy treated every non-`v==1`
//!   object as flat. Flat documents without `v` still load literally.
//!
//! Explicitly unimplemented here: ACL checks (`kv_read`/`kv_write`/
//! `kv_list`), wire ops and response frames, group-commit/fsync policy,
//! WAL compaction, and presence/scheduler interaction. `list` is an
//! unfiltered convenience capped at [`KV_LIST_LIMIT`]; the broker must
//! use [`KvStore::list_filtered`] so policy filtering happens before
//! the cap, matching legacy `[... if allowed][:1000]`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum keys returned by [`KvStore::list`] and
/// [`KvStore::list_filtered`], matching legacy `[:1000]`.
pub const KV_LIST_LIMIT: usize = 1000;
/// WAL record tag for a put, matching legacy `{"t":"kv",..}`.
pub const RECORD_PUT: &str = "kv";
/// WAL record tag for a delete, matching legacy `{"t":"kv_del",..}`.
pub const RECORD_DELETE: &str = "kv_del";
/// Snapshot document version, matching legacy `{"v":1,..}`.
pub const SNAPSHOT_VERSION: u32 = 1;

/// One stored key: any JSON value (including null) plus an optional
/// absolute unix-seconds expiry. `None` means the key never expires.
#[derive(Clone, Debug, PartialEq)]
pub struct KvEntry {
    pub value: Value,
    pub exp: Option<f64>,
}

/// Validation failure. Durability-callback errors are returned as the
/// callback's own error type, never wrapped here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvError {
    /// Put/delete with an empty key (legacy `"key required"`).
    EmptyKey,
    /// Put with a non-finite `now` or computed expiry. Rejected before
    /// any durability work so the JSON record (where serde renders
    /// non-finite `f64` as null) can never diverge from memory.
    NonFiniteTime,
    /// Snapshot document that is not valid JSON, not a JSON object, has
    /// an unsupported version, has a non-object `kv`/`exp` map, or has a
    /// malformed `exp` entry for a stored key.
    BadSnapshot(String),
}

impl std::fmt::Display for KvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KvError::EmptyKey => write!(f, "key required"),
            KvError::NonFiniteTime => write!(f, "non-finite time"),
            KvError::BadSnapshot(detail) => write!(f, "bad snapshot: {detail}"),
        }
    }
}

impl std::error::Error for KvError {}

/// True exactly when `now > exp`, mirroring legacy `kv_expired`.
/// A missing expiry never expires; `now == exp` is still live.
///
/// Callers must pass a finite `now` and, when present, a finite `exp`.
/// Non-finite inputs follow plain float comparison (`NaN` never
/// expires, `+inf` expires every finite entry) and are a logic error:
/// new writes with non-finite times are rejected by
/// [`KvStore::prepare_put`].
pub fn expired(exp: Option<f64>, now: f64) -> bool {
    matches!(exp, Some(e) if now > e)
}

/// Absolute expiry for a `ttl_ms` request at `now`.
///
/// Legacy computes `exp = now + ttl/1000` only when `ttl` is truthy
/// (Python `if ttl`): `None` and exactly `0`/`0.0` (including `-0.0`)
/// mean no expiry, while any other finite value — integer or
/// fractional, positive or negative — yields `now + ttl/1000`.
/// Fractional milliseconds are preserved exactly (no rounding to
/// integer ms): `0.1` means `now + 0.0001`, matching legacy float
/// division. A negative TTL yields an already-past expiry (the write
/// is still valid and durable; reads treat it as expired immediately).
///
/// Callers must pass a finite `now` and, when present, a finite `ttl`;
/// non-finite inputs yield a non-finite expiry that
/// [`KvStore::prepare_put_f64`] rejects. See
/// [`expiry_for_ttl`] for the integer convenience wrapper.
pub fn expiry_for_ttl_f64(ttl_ms: Option<f64>, now: f64) -> Option<f64> {
    match ttl_ms {
        None => None,
        // Matches `0.0` and `-0.0` (float `==`, like Python falsy).
        Some(0.0) => None,
        Some(t) => Some(now + t / 1000.0),
    }
}

/// Integer convenience wrapper around [`expiry_for_ttl_f64`]:
/// `None`/`Some(0)` mean no expiry, else `now + ms/1000`.
/// Exact for all `i64` inputs (same `as f64` conversion as before).
pub fn expiry_for_ttl(ttl_ms: Option<i64>, now: f64) -> Option<f64> {
    expiry_for_ttl_f64(ttl_ms.map(|ms| ms as f64), now)
}

/// Parsed put body. The `t` tag is matched before this parse, and any
/// extra members are ignored, mirroring the legacy reader that only
/// looks at known fields.
#[derive(Deserialize)]
struct PutRecord {
    key: String,
    #[serde(default)]
    value: Value,
    #[serde(default)]
    exp: Option<f64>,
}

#[derive(Serialize)]
struct PutRecordRef<'a> {
    t: &'a str,
    key: &'a str,
    value: &'a Value,
    exp: Option<f64>,
}

#[derive(Serialize)]
struct DeleteRecordRef<'a> {
    t: &'a str,
    key: &'a str,
}

fn canonical_put_line(key: &str, value: &Value, exp: Option<f64>) -> String {
    serde_json::to_string(&PutRecordRef { t: RECORD_PUT, key, value, exp })
        .expect("kv put record serializes")
}

fn canonical_delete_line(key: &str) -> String {
    serde_json::to_string(&DeleteRecordRef { t: RECORD_DELETE, key })
        .expect("kv delete record serializes")
}

/// Validated put awaiting durability: the canonical record line plus the
/// exact state change to apply after the durability callback succeeds.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingPut {
    key: String,
    value: Value,
    exp: Option<f64>,
    line: String,
}

impl PendingPut {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn exp(&self) -> Option<f64> {
        self.exp
    }

    /// The canonical `{"t":"kv",..}` line the durability callback durably
    /// stores before this change may become visible.
    pub fn record_line(&self) -> &str {
        &self.line
    }
}

/// Validated delete awaiting durability. `found` is key presence at
/// prepare time, independent of the stored value (JSON null counts as
/// present) and of expiry, matching legacy delete-ignores-expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingDelete {
    key: String,
    found: bool,
    line: String,
}

impl PendingDelete {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn found(&self) -> bool {
        self.found
    }

    /// The canonical `{"t":"kv_del",..}` line the durability callback
    /// durably stores before this change may become visible.
    pub fn record_line(&self) -> &str {
        &self.line
    }
}

/// Outcome of replaying one record line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineOutcome {
    /// Blank line; ignored, not counted as malformed.
    IgnoredBlank,
    /// Live put applied in record order.
    PutApplied,
    /// Delete applied in record order.
    DeleteApplied,
    /// Already-expired put applied as a tombstone: any older value for
    /// the key is suppressed instead of resurrected.
    ExpiredSuppressed,
    /// Unparseable or structurally invalid record; skipped.
    SkippedMalformed,
}

/// Aggregate outcome of replaying a record sequence at one `now`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplayReport {
    pub puts: usize,
    pub deletes: usize,
    pub expired_suppressed: usize,
    pub malformed: usize,
}

impl ReplayReport {
    /// Records applied to state (puts + deletes + expired tombstones).
    pub fn applied(&self) -> usize {
        self.puts + self.deletes + self.expired_suppressed
    }
}

/// Outcome of restoring one snapshot document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Keys merged into the store, including already-expired ones:
    /// expiry is enforced at read time, matching the legacy load path
    /// that updates `kv_store`/`kv_exp` without filtering.
    pub loaded: usize,
    /// Orphaned `exp` entries (a numeric expiry for a key with no value
    /// in `kv`). Non-string keys are impossible in JSON objects.
    /// A malformed `exp` value for a stored key is not skipped: restore
    /// fails atomically with [`KvError::BadSnapshot`] and leaves the
    /// store untouched instead of dropping the TTL.
    pub skipped: usize,
}

/// Live-only snapshot image; serializes as `{"v":1,"kv":{..},"exp":{..}}`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Snapshot {
    pub v: u32,
    pub kv: BTreeMap<String, Value>,
    pub exp: BTreeMap<String, f64>,
}

/// In-memory KV state: stored entries keyed by exact key string.
/// Iteration order is sorted, matching legacy `sorted(...)` lists.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KvStore {
    entries: BTreeMap<String, KvEntry>,
}

impl KvStore {
    pub fn new() -> Self {
        KvStore { entries: BTreeMap::new() }
    }

    /// Stored entries, including expired-but-not-yet-purged ones.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Live (non-expired) entries at `now`. Callers must pass a
    /// finite `now` (see [`expired`]).
    pub fn live_len(&self, now: f64) -> usize {
        self.entries.values().filter(|e| !expired(e.exp, now)).count()
    }

    /// Validate a put and render its canonical record line. Pure: no
    /// state changes. Rejects empty keys and non-finite `now`/ttl/expiry
    /// before any durability work, so the JSON record can never
    /// diverge from memory (serde renders non-finite `f64` as null).
    /// Fractional `ttl_ms` is preserved exactly via
    /// [`expiry_for_ttl_f64`] (no rounding): `Some(0.1)` means
    /// `now + 0.0001`, matching legacy `now + ttl/1000`.
    pub fn prepare_put_f64(
        &self,
        key: &str,
        value: Value,
        ttl_ms: Option<f64>,
        now: f64,
    ) -> Result<PendingPut, KvError> {
        if key.is_empty() {
            return Err(KvError::EmptyKey);
        }
        if !now.is_finite() {
            return Err(KvError::NonFiniteTime);
        }
        if let Some(t) = ttl_ms {
            if !t.is_finite() {
                return Err(KvError::NonFiniteTime);
            }
        }
        let exp = expiry_for_ttl_f64(ttl_ms, now);
        if let Some(e) = exp {
            if !e.is_finite() {
                return Err(KvError::NonFiniteTime);
            }
        }
        Ok(PendingPut {
            line: canonical_put_line(key, &value, exp),
            key: key.to_string(),
            value,
            exp,
        })
    }

    /// Integer convenience wrapper around [`KvStore::prepare_put_f64`].
    /// Exact for all `i64` inputs.
    pub fn prepare_put(
        &self,
        key: &str,
        value: Value,
        ttl_ms: Option<i64>,
        now: f64,
    ) -> Result<PendingPut, KvError> {
        self.prepare_put_f64(key, value, ttl_ms.map(|ms| ms as f64), now)
    }

    /// Run the durability callback for a prepared put, then apply the
    /// in-memory change only if it succeeds. On callback error the
    /// store is untouched and the callback's error is returned as-is.
    pub fn commit_put<E>(
        &mut self,
        pending: PendingPut,
        mut durability: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<(), E> {
        durability(&pending.line)?;
        self.entries.insert(pending.key, KvEntry { value: pending.value, exp: pending.exp });
        Ok(())
    }

    /// Validate a delete and render its canonical record line. Pure: no
    /// state changes. `found` reflects key presence (null-valued and
    /// expired-but-stored keys count as present).
    pub fn prepare_delete(&self, key: &str) -> Result<PendingDelete, KvError> {
        if key.is_empty() {
            return Err(KvError::EmptyKey);
        }
        Ok(PendingDelete {
            line: canonical_delete_line(key),
            found: self.entries.contains_key(key),
            key: key.to_string(),
        })
    }

    /// Run the durability callback for a prepared delete, then remove
    /// the key only if it succeeds. Returns prepare-time `found`. On
    /// callback error the store is untouched.
    pub fn commit_delete<E>(
        &mut self,
        pending: PendingDelete,
        mut durability: impl FnMut(&str) -> Result<(), E>,
    ) -> Result<bool, E> {
        durability(&pending.line)?;
        self.entries.remove(&pending.key);
        Ok(pending.found)
    }

    /// Live value for `key` at `now`, or `None` when missing or expired.
    /// Pure: never purges; the broker calls [`KvStore::purge_expired`]
    /// explicitly instead of relying on read-path side effects.
    /// Callers must pass a finite `now` (see [`expired`]).
    pub fn get(&self, key: &str, now: f64) -> Option<&Value> {
        self.entry(key, now).map(|e| &e.value)
    }

    /// Live entry (value plus expiry) for `key` at `now`.
    /// Callers must pass a finite `now` (see [`expired`]).
    pub fn entry(&self, key: &str, now: f64) -> Option<&KvEntry> {
        self.entries.get(key).filter(|e| !expired(e.exp, now))
    }

    /// Stored entry regardless of expiry (introspection for tests and
    /// the future broker; reads must use [`KvStore::entry`]).
    pub fn stored(&self, key: &str) -> Option<&KvEntry> {
        self.entries.get(key)
    }

    /// Sorted live keys with `prefix` at `now`, capped at
    /// [`KV_LIST_LIMIT`]. Unfiltered convenience for tests and
    /// introspection; it performs no authorization. The broker must use
    /// [`KvStore::list_filtered`] so ACL grants are applied before the
    /// cap, matching legacy `[... if allowed][:1000]`.
    /// Callers must pass a finite `now` (see [`expired`]).
    pub fn list(&self, prefix: &str, now: f64) -> Vec<String> {
        self.list_filtered(prefix, now, |_| true)
    }

    /// Sorted live keys with `prefix` at `now` for which `allow`
    /// returns true, capped at [`KV_LIST_LIMIT`] after filtering.
    /// The predicate runs in sorted key order; only allowed keys count
    /// toward the cap, so a policy deny of the first 1000+ keys still
    /// surfaces later allowed keys. This core performs no authorization
    /// itself: the broker supplies its per-key grant check.
    /// Callers must pass a finite `now` (see [`expired`]).
    pub fn list_filtered(
        &self,
        prefix: &str,
        now: f64,
        mut allow: impl FnMut(&str) -> bool,
    ) -> Vec<String> {
        let mut out = Vec::new();
        for (key, entry) in self.entries.iter() {
            if out.len() >= KV_LIST_LIMIT {
                break;
            }
            if !key.starts_with(prefix) || expired(entry.exp, now) {
                continue;
            }
            if !allow(key) {
                continue;
            }
            out.push(key.clone());
        }
        out
    }

    /// Drop expired entries; returns the number removed. Snapshots only
    /// ever contain live keys, so purging before snapshotting is a
    /// memory optimization, never a correctness requirement.
    /// Callers must pass a finite `now` (see [`expired`]).
    pub fn purge_expired(&mut self, now: f64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| !expired(e.exp, now));
        before - self.entries.len()
    }

    /// Replay one record line at `now`, in caller-provided order.
    ///
    /// Record order decides: a live put sets the key, a delete clears
    /// it, and an already-expired put clears it too (tombstone), so a
    /// newer expired write always suppresses an older value. Blank
    /// lines are ignored; malformed records are skipped and reported.
    /// Keys apply verbatim (new-write validation is a `prepare_*`
    /// concern, matching the legacy replay path that never validates).
    /// Callers must pass a finite `now` (see [`expired`]).
    pub fn replay_line(&mut self, line: &str, now: f64) -> LineOutcome {
        if line.trim().is_empty() {
            return LineOutcome::IgnoredBlank;
        }
        let record: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return LineOutcome::SkippedMalformed,
        };
        let obj = match record.as_object() {
            Some(o) => o,
            None => return LineOutcome::SkippedMalformed,
        };
        match obj.get("t").and_then(|t| t.as_str()) {
            Some(RECORD_PUT) => {
                let parsed: PutRecord = match serde_json::from_value(record) {
                    Ok(p) => p,
                    Err(_) => return LineOutcome::SkippedMalformed,
                };
                if expired(parsed.exp, now) {
                    self.entries.remove(&parsed.key);
                    LineOutcome::ExpiredSuppressed
                } else {
                    self.entries.insert(
                        parsed.key,
                        KvEntry { value: parsed.value, exp: parsed.exp },
                    );
                    LineOutcome::PutApplied
                }
            }
            Some(RECORD_DELETE) => match obj.get("key").and_then(|k| k.as_str()) {
                Some(key) => {
                    self.entries.remove(key);
                    LineOutcome::DeleteApplied
                }
                None => LineOutcome::SkippedMalformed,
            },
            _ => LineOutcome::SkippedMalformed,
        }
    }

    /// Replay a record sequence in order at one fixed `now`, mirroring
    /// the legacy restart scan that captures `now` once up front.
    /// Callers must pass a finite `now` (see [`expired`]).
    pub fn replay_lines<'a, I>(&mut self, lines: I, now: f64) -> ReplayReport
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut report = ReplayReport::default();
        for line in lines {
            match self.replay_line(line, now) {
                LineOutcome::IgnoredBlank => {}
                LineOutcome::PutApplied => report.puts += 1,
                LineOutcome::DeleteApplied => report.deletes += 1,
                LineOutcome::ExpiredSuppressed => report.expired_suppressed += 1,
                LineOutcome::SkippedMalformed => report.malformed += 1,
            }
        }
        report
    }

    /// Live-only snapshot image at `now`, matching legacy `snapshot_kv`
    /// (live `kv` plus `exp` restricted to live keys).
    /// Callers must pass a finite `now` (see [`expired`]).
    pub fn snapshot(&self, now: f64) -> Snapshot {
        let mut kv = BTreeMap::new();
        let mut exp = BTreeMap::new();
        for (key, entry) in &self.entries {
            if expired(entry.exp, now) {
                continue;
            }
            if let Some(e) = entry.exp {
                exp.insert(key.clone(), e);
            }
            kv.insert(key.clone(), entry.value.clone());
        }
        Snapshot { v: SNAPSHOT_VERSION, kv, exp }
    }

    /// Serialize [`KvStore::snapshot`] to its canonical document form.
    /// Callers must pass a finite `now` (see [`expired`]).
    pub fn snapshot_json(&self, now: f64) -> String {
        serde_json::to_string(&self.snapshot(now)).expect("snapshot serializes")
    }

    /// Merge a snapshot document into the store.
    ///
    /// Accepts the `{"v":1,"kv":{..},"exp":{..}}` form plus the legacy
    /// flat form (a JSON object without a top-level `v` member, loaded
    /// literally as bare key/value pairs with no expiry). Any document
    /// carrying a top-level `v` member is treated as versioned and must
    /// be exactly version 1; unsupported versions fail instead of
    /// loading `v`/`kv`/`exp` metadata as user keys. Non-object
    /// documents are rejected so a corrupt snapshot can never look like
    /// an empty store; the broker decides whether to log-and-continue
    /// like the legacy load path.
    ///
    /// Version-1 restores are atomic: every `exp` value is validated as
    /// a finite number before any state changes. A malformed `exp` for
    /// a stored key fails with [`KvError::BadSnapshot`] and leaves the
    /// store untouched instead of dropping the TTL and making corrupt
    /// data immortal. Orphaned numeric `exp` entries (no matching `kv`
    /// value) are inert and counted as `skipped`.
    pub fn restore_snapshot(&mut self, doc: &str) -> Result<RestoreReport, KvError> {
        let parsed: Value = serde_json::from_str(doc)
            .map_err(|e| KvError::BadSnapshot(format!("invalid json: {e}")))?;
        let obj = parsed
            .as_object()
            .ok_or_else(|| KvError::BadSnapshot("not an object".to_string()))?;
        if obj.contains_key("v") {
            if obj.get("v").and_then(|v| v.as_u64()) != Some(SNAPSHOT_VERSION as u64) {
                return Err(KvError::BadSnapshot(format!(
                    "unsupported snapshot version: {}",
                    obj.get("v").map(|v| v.to_string()).unwrap_or_default()
                )));
            }
            let kv_obj = match obj.get("kv") {
                None => None,
                Some(Value::Object(o)) => Some(o),
                Some(_) => {
                    return Err(KvError::BadSnapshot("kv is not an object".to_string()))
                }
            };
            let exp_obj = match obj.get("exp") {
                None => None,
                Some(Value::Object(o)) => Some(o),
                Some(_) => {
                    return Err(KvError::BadSnapshot("exp is not an object".to_string()))
                }
            };
            if let Some(exp_obj) = exp_obj {
                for (key, value) in exp_obj {
                    match value.as_f64() {
                        Some(e) if e.is_finite() => {}
                        _ => {
                            return Err(KvError::BadSnapshot(format!(
                                "malformed exp for key {key:?}"
                            )))
                        }
                    }
                }
            }
            let mut staged: Vec<(String, Value, Option<f64>)> = Vec::new();
            if let Some(kv_obj) = kv_obj {
                staged.reserve(kv_obj.len());
                for (key, value) in kv_obj {
                    let exp = exp_obj.and_then(|e| e.get(key)).and_then(|e| e.as_f64());
                    staged.push((key.clone(), value.clone(), exp));
                }
            }
            let mut report = RestoreReport::default();
            for (key, value, exp) in staged {
                self.entries.insert(key, KvEntry { value, exp });
                report.loaded += 1;
            }
            if let Some(exp_obj) = exp_obj {
                let in_kv = |k: &str| {
                    kv_obj.map(|o| o.contains_key(k)).unwrap_or(false)
                };
                report.skipped += exp_obj.keys().filter(|k| !in_kv(k)).count();
            }
            return Ok(report);
        }
        let mut report = RestoreReport::default();
        for (key, value) in obj {
            self.entries.insert(key.clone(), KvEntry { value: value.clone(), exp: None });
            report.loaded += 1;
        }
        Ok(report)
    }
}

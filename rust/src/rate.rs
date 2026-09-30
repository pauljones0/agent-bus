//! Pure post rate-limit core: ordered first-match topic rules, fallback
//! global rate, and per-agent-and-rule token buckets.
//!
//! Native port of the transitional Python broker's post throttling
//! (`broker.py` `rate_rule_for`/`rate_take` and the `post` ACL-then-rate
//! gate, read as text only), without any wire, broker, filesystem,
//! network, or environment interaction. This module owns rate shapes,
//! validation, first-match selection, and bucket math. Wire integration
//! (shared buckets, `rate_limited` accounting, `retry_after_ms` hints)
//! stays with the builder-owned `wire.rs`, and token-file loading stays
//! with `acl.rs` (which stores a validated [`RateConfig`] per policy).
//!
//! Preserved contract:
//! - First matching `topic_rates` pattern wins (file order, not sorted);
//!   else the agent-global `rate_per_s`; admin tokens (`agent == "*"`,
//!   checked by the caller, never here) bypass. Missing/null rates mean
//!   unlimited.
//! - Buckets are keyed by `(agent claimed name, rule pattern or "*")`,
//!   shared across connections and tokens for one agent (matching the
//!   legacy global `rate_buckets` dict). Refill is `per_s` per second,
//!   one token per post; burst is `max(per_s, 1)` so every accepted
//!   positive rate can allow a whole post (integer rates unchanged).
//! - `retry_after_ms` is half-even 1-decimal `(1-tokens)/per_s*1000`
//!   (matching legacy `round(...,1)` via `presence::round1_py` at the
//!   wire layer), always finite for accepted rates.
//! - Shared buckets survive policy changes between requests (same agent,
//!   different token rates): refill for elapsed time uses
//!   `min(old_per_s, new_per_s)` and tokens cap at the new burst, so a
//!   faster policy cannot fabricate credit for old time, a reduction
//!   cannot retain over-burst, and a formerly slow bucket is never
//!   locked out.
//!
//! Intentional corrections (fail-closed, never silent-unlimited):
//! - Malformed configs reject at load with an explicit reason (no panic,
//!   no crash-per-request, no silent unlimited): `rate_per_s` and every
//!   `topic_rates` value must be a JSON number, finite, `> 0`, with a
//!   finite `1000/per_s` retry hint; patterns must be valid [`Pattern`]s;
//!   truthy non-object `topic_rates` containers (e.g. `[1]`) reject.
//!   Falsy containers (`0`/`false`/`""`/`[]`/`{}`/`null`/missing) mean no
//!   topic rules, matching legacy `or {}`. Numeric strings (legacy
//!   `float("2")`) reject: JSON numbers are required, consistent with
//!   `acl` `exp` strictness. Rates too small for a finite retry hint
//!   (e.g. `5e-324`, `1e-310`) reject explicitly instead of emitting
//!   non-finite JSON.
//! - Backwards clocks clamp (`elapsed = max(0, now-last)`, `last` never
//!   moves backwards). Legacy drains tokens on negative `now-last`
//!   (a clock glitch penalizes); native treats it as no refill/drain.
//! - Burst is `max(per_s, 1)` (fractional `> 0` valid, first request
//!   succeeds). Legacy `burst == per_s` never allows `0.5/s` (burst
//!   `0.5 < 1`, retry hints misleading); that is a known product defect,
//!   not preserved parity.
//!
//! No IO is performed: all inputs are caller-provided `&str`/`&Value`/
//! `f64`, and all outputs are pure decisions or preserved data. Clocks
//! must be finite (callers fail `non-finite time` before calling here).

use std::collections::HashMap;

use serde_json::Value;

use crate::acl::Pattern;

/// Burst capacity for a validated rate: `max(per_s, 1)` so every
/// accepted positive rate can hold a whole post. Integer and `>= 1`
/// fractional rates keep legacy `per_s` burst exactly.
pub fn burst_capacity(per_s: f64) -> f64 {
    debug_assert!(per_s.is_finite() && per_s > 0.0);
    per_s.max(1.0)
}

/// One validated topic-rate rule: file-ordered pattern plus rate.
#[derive(Clone, Debug, PartialEq)]
pub struct RateRule {
    /// Original pattern text (bucket key, diagnostics; policy, not secret).
    pub pattern_raw: String,
    /// Validated glob (strict [`Pattern`], same as publish grants).
    pub pattern: Pattern,
    /// Requests per second; always finite, `> 0`, with finite
    /// `1000/per_s` retry hint (validated at load).
    pub per_s: f64,
}

/// Validated per-token rate policy: ordered topic rules plus fallback.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct RateConfig {
    /// Global fallback (`rate_per_s`), or `None` for unlimited when no
    /// topic rule matches. Always finite, `> 0`, with finite
    /// `1000/per_s` retry hint when present.
    pub global: Option<f64>,
    /// Topic rules in first-match order: file order for
    /// [`crate::acl::TokenStore::from_json_str`], sorted-key order for
    /// [`crate::acl::Policy::from_json`] (whose `Value` input has no file
    /// order; single-entry configs agree).
    pub rules: Vec<RateRule>,
}

impl RateConfig {
    /// True when no topic rules and no global (unlimited).
    pub fn is_unlimited(&self) -> bool {
        self.global.is_none() && self.rules.is_empty()
    }

    /// First-match selection, mirroring `rate_rule_for` (admin bypass is
    /// the caller's check, never here). Returns `(rule_key, per_s)` with
    /// `rule_key` the matching pattern or `"*"` for the global fallback,
    /// or `None` when unlimited.
    pub fn select(&self, topic: &str) -> Option<(&str, f64)> {
        for rule in &self.rules {
            if rule.pattern.matches(topic) {
                return Some((rule.pattern_raw.as_str(), rule.per_s));
            }
        }
        self.global.map(|per_s| ("*", per_s))
    }
}

/// Python `or {}` falsiness for `topic_rates` containers, matching
/// `wire::is_falsy` (kept here as the single source; wire reuses it):
/// `null`, `false`, numeric zero, empty string/array/object are falsy.
pub fn is_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i == 0
            } else if let Some(u) = n.as_u64() {
                u == 0
            } else {
                n.as_f64().is_some_and(|f| f == 0.0)
            }
        }
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(m) => m.is_empty(),
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Validate one rate value: must be a JSON number, finite, `> 0`,
/// with a finite `1000/per_s` worst-case retry hint (so denied posts
/// never emit non-finite JSON). `field` names the config location for
/// diagnostics (policy, not secret).
pub fn parse_rate_value(v: &Value, field: &str) -> Result<f64, String> {
    let n = v
        .as_f64()
        .ok_or_else(|| format!("{field} must be a number (got {})", type_name(v)))?;
    if !n.is_finite() {
        return Err(format!("{field} must be finite (got {n})"));
    }
    if n <= 0.0 {
        return Err(format!("{field} must be > 0 (got {n})"));
    }
    if !(1000.0 / n).is_finite() {
        return Err(format!("{field} too small for finite retry hint (got {n})"));
    }
    Ok(n)
}

/// Validate the global fallback: missing/null means unlimited.
pub fn parse_global(v: Option<&Value>) -> Result<Option<f64>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(val) => Ok(Some(parse_rate_value(val, "rate_per_s")?)),
    }
}

/// Collapse duplicate patterns to legacy dict semantics: last value wins,
/// first insertion position kept (Python `d[k]=v` / `json.load`).
/// Input order is document/flag order; output preserves first-seen order
/// with each pattern's final value. Sorted `Value` inputs have no duplicates
/// (BTreeMap collapsed), so this is a no-op there. Wire/file duplicate JSON
/// keys and repeated CLI `--topic-rate` flags both funnel through here via
/// [`parse_rules_ordered`].
pub fn dedup_ordered_pairs(pairs: Vec<(String, Value)>) -> Vec<(String, Value)> {
    use std::collections::HashMap;
    let mut index: HashMap<String, usize> = HashMap::with_capacity(pairs.len());
    let mut out: Vec<(String, Value)> = Vec::with_capacity(pairs.len());
    for (pat, val) in pairs {
        if let Some(&i) = index.get(&pat) {
            out[i].1 = val;
        } else {
            index.insert(pat.clone(), out.len());
            out.push((pat, val));
        }
    }
    out
}

/// Validate ordered topic-rate pairs into first-match rules. `pairs` is
/// file order (text loads), wire-document order (issue requests), flag order
/// (CLI), or sorted order (`Value` loads); validation is order-independent
/// except for the preserved first-match positions. Duplicate patterns collapse
/// first (last value, first position) so a repeated flag/key updates the value
/// without moving the rule, matching legacy dict assignment.
pub fn parse_rules_ordered(pairs: Vec<(String, Value)>) -> Result<Vec<RateRule>, String> {
    let pairs = dedup_ordered_pairs(pairs);
    let mut rules = Vec::with_capacity(pairs.len());
    for (raw, val) in pairs {
        let pattern =
            Pattern::new(&raw).map_err(|e| format!("topic_rates[{raw:?}]: {e}"))?;
        let field = format!("topic_rates[{raw:?}]");
        let per_s = parse_rate_value(&val, &field)?;
        rules.push(RateRule { pattern_raw: raw, pattern, per_s });
    }
    Ok(rules)
}

/// Validate a `topic_rates` container from a sorted `Value` (ACL/file
/// loads without file order): falsy means no rules, objects yield
/// sorted-order pairs, truthy non-objects reject.
pub fn parse_topic_rates_from_value(v: Option<&Value>) -> Result<Vec<RateRule>, String> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(val) if is_falsy(val) => Ok(Vec::new()),
        Some(Value::Object(map)) => {
            let pairs: Vec<(String, Value)> =
                map.iter().map(|(k, val)| (k.clone(), val.clone())).collect();
            parse_rules_ordered(pairs)
        }
        Some(other) => Err(format!(
            "topic_rates must be an object (got {})",
            type_name(other)
        )),
    }
}

/// File-ordered `topic_rates` container for text loads: objects collect
/// `(pattern, value)` in document order, falsy/missing means no rules,
/// truthy non-objects fail (malformed, never silent-unlimited).
#[derive(Clone, Debug, Default)]
pub struct OrderedTopicRates(pub Vec<(String, Value)>);

impl<'de> serde::Deserialize<'de> for OrderedTopicRates {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};

        struct RatesVisitor;

        impl<'de> Visitor<'de> for RatesVisitor {
            type Value = OrderedTopicRates;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("topic_rates object or falsy value")
            }

            fn visit_unit<E>(self) -> Result<OrderedTopicRates, E>
            where
                E: de::Error,
            {
                Ok(OrderedTopicRates(Vec::new()))
            }

            fn visit_none<E>(self) -> Result<OrderedTopicRates, E>
            where
                E: de::Error,
            {
                Ok(OrderedTopicRates(Vec::new()))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<OrderedTopicRates, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                serde::Deserialize::deserialize(deserializer)
            }

            fn visit_bool<E>(self, b: bool) -> Result<OrderedTopicRates, E>
            where
                E: de::Error,
            {
                if b {
                    Err(de::Error::custom("topic_rates must be an object (got boolean)"))
                } else {
                    Ok(OrderedTopicRates(Vec::new()))
                }
            }

            fn visit_i64<E>(self, n: i64) -> Result<OrderedTopicRates, E>
            where
                E: de::Error,
            {
                if n == 0 {
                    Ok(OrderedTopicRates(Vec::new()))
                } else {
                    Err(de::Error::custom("topic_rates must be an object (got number)"))
                }
            }

            fn visit_u64<E>(self, n: u64) -> Result<OrderedTopicRates, E>
            where
                E: de::Error,
            {
                if n == 0 {
                    Ok(OrderedTopicRates(Vec::new()))
                } else {
                    Err(de::Error::custom("topic_rates must be an object (got number)"))
                }
            }

            fn visit_f64<E>(self, f: f64) -> Result<OrderedTopicRates, E>
            where
                E: de::Error,
            {
                if f == 0.0 {
                    Ok(OrderedTopicRates(Vec::new()))
                } else {
                    Err(de::Error::custom("topic_rates must be an object (got number)"))
                }
            }

            fn visit_str<E>(self, s: &str) -> Result<OrderedTopicRates, E>
            where
                E: de::Error,
            {
                if s.is_empty() {
                    Ok(OrderedTopicRates(Vec::new()))
                } else {
                    Err(de::Error::custom("topic_rates must be an object (got string)"))
                }
            }

            fn visit_string<E>(self, s: String) -> Result<OrderedTopicRates, E>
            where
                E: de::Error,
            {
                self.visit_str(&s)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<OrderedTopicRates, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // Empty array is falsy (no rules); non-empty is malformed.
                match seq.next_element::<serde::de::IgnoredAny>()? {
                    None => Ok(OrderedTopicRates(Vec::new())),
                    Some(_) => Err(de::Error::custom(
                        "topic_rates must be an object (got array)",
                    )),
                }
            }

            fn visit_map<A>(self, mut map: A) -> Result<OrderedTopicRates, A::Error>
            where
                A: MapAccess<'de>,
            {
                // `MapAccess` yields entries in document order; collecting
                // into `Vec` preserves first-match file order (unlike the
                // default `BTreeMap`-backed `Value`, which sorts).
                let mut pairs = Vec::new();
                while let Some((k, val)) =
                    map.next_entry::<String, Value>()?
                {
                    pairs.push((k, val));
                }
                Ok(OrderedTopicRates(pairs))
            }
        }

        deserializer.deserialize_any(RatesVisitor)
    }
}

// ---------------------------------------------------------------------------
// Token buckets
// ---------------------------------------------------------------------------

/// One token bucket: burst `max(per_s, 1)`, refill `per_s`/s, one
/// token per post. `tokens` stays in `[0, burst]`; `last` never moves
/// backwards; `per_s` is the last effective rate (for shared-bucket
/// policy changes).
#[derive(Clone, Debug, PartialEq)]
pub struct Bucket {
    tokens: f64,
    last: f64,
    per_s: f64,
}

impl Bucket {
    /// Fresh bucket with full burst at `now` (both finite; `per_s` finite
    /// `> 0` with finite retry hint, validated at load).
    pub fn new(per_s: f64, now: f64) -> Self {
        debug_assert!(per_s.is_finite() && per_s > 0.0);
        debug_assert!((1000.0 / per_s).is_finite());
        debug_assert!(now.is_finite());
        Bucket { tokens: burst_capacity(per_s), last: now, per_s }
    }

    /// Current tokens (for tests; always in `[0, burst]`).
    pub fn tokens(&self) -> f64 {
        self.tokens
    }

    /// Last refill clock (for tests; never moves backwards).
    pub fn last(&self) -> f64 {
        self.last
    }

    /// Last effective rate (for tests; updated on every take).
    pub fn per_s(&self) -> f64 {
        self.per_s
    }

    /// Take one token at `now` under rate `per_s`. Returns
    /// `(allowed, retry_after_ms)` with `retry_after_ms == 0.0` when
    /// allowed, else the finite unrounded `(1-tokens)/per_s*1000` hint
    /// (wire rounds half-even 1-decimal). Backwards clocks
    /// (`now < last`) refill nothing and move nothing (but still adopt
    /// the new rate and cap). Policy changes refill elapsed time at
    /// `min(old, new)` and cap at the new burst, so faster policies
    /// cannot fabricate old credit, reductions cannot retain over-burst,
    /// and slow buckets never lock out.
    pub fn take(&mut self, per_s: f64, now: f64) -> (bool, f64) {
        debug_assert!(per_s.is_finite() && per_s > 0.0);
        debug_assert!((1000.0 / per_s).is_finite());
        debug_assert!(now.is_finite());
        debug_assert!(self.last.is_finite());
        debug_assert!(self.per_s.is_finite() && self.per_s > 0.0);
        let elapsed = (now - self.last).max(0.0);
        let refill_rate = self.per_s.min(per_s);
        let cap = burst_capacity(per_s);
        let tokens = (self.tokens + elapsed * refill_rate).min(cap);
        // Adopt the new policy even on deny/backwards so the next
        // refill uses it (no sticky penalty or sticky credit).
        self.per_s = per_s;
        if now > self.last {
            self.last = now;
        }
        if tokens >= 1.0 {
            self.tokens = tokens - 1.0;
            debug_assert!((1000.0 / per_s).is_finite());
            (true, 0.0)
        } else {
            self.tokens = tokens;
            let retry = ((1.0 - tokens) / per_s * 1000.0).max(0.0);
            debug_assert!(retry.is_finite());
            (false, retry)
        }
    }
}

/// In-memory `(agent, rule)` buckets, mirroring the legacy global
/// `rate_buckets` dict (never WAL, never cleared on token change).
#[derive(Clone, Debug, Default)]
pub struct RateLimiter {
    buckets: HashMap<(String, String), Bucket>,
}

impl RateLimiter {
    /// Empty limiter (no buckets until first limited post).
    pub fn new() -> Self {
        RateLimiter { buckets: HashMap::new() }
    }

    /// Number of live buckets (for tests).
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// True when no buckets exist yet.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Check-and-take for `(agent, rule_key)` at `per_s`/`now` (both
    /// finite, `per_s > 0` with finite retry hint; callers fail
    /// `non-finite time` first). First use creates a full-burst bucket;
    /// later uses share it across connections/tokens for one agent.
    /// Policy changes refill elapsed time at `min(old, new)` and cap at
    /// the new burst (no fabricated credit, no over-burst retention, no
    /// lockout).
    pub fn check(
        &mut self,
        agent: &str,
        rule_key: &str,
        per_s: f64,
        now: f64,
    ) -> (bool, f64) {
        debug_assert!(per_s.is_finite() && per_s > 0.0);
        debug_assert!((1000.0 / per_s).is_finite());
        debug_assert!(now.is_finite());
        let key = (agent.to_string(), rule_key.to_string());
        let bucket =
            self.buckets.entry(key).or_insert_with(|| Bucket::new(per_s, now));
        bucket.take(per_s, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn burst_refill_and_retry_match_legacy_math() {
        // per_s=2: burst 2, refill 2/s. Fixed clock, no time passes.
        let mut b = Bucket::new(2.0, 100.0);
        assert_eq!(b.take(2.0, 100.0), (true, 0.0));
        assert_eq!(b.take(2.0, 100.0), (true, 0.0));
        // Exhausted: tokens 0, retry (1-0)/2*1000=500.
        let (ok, retry) = b.take(2.0, 100.0);
        assert!(!ok);
        assert!((retry - 500.0).abs() < 1e-9, "{retry}");
        // +0.25s refills 0.5 tokens: still short, retry (1-0.5)/2*1000=250.
        let (ok, retry) = b.take(2.0, 100.25);
        assert!(!ok);
        assert!((retry - 250.0).abs() < 1e-9, "{retry}");
        // +0.5s total refills 1.0: allowed.
        assert_eq!(b.take(2.0, 100.5), (true, 0.0));
        // Burst cap: long idle refills to per_s, not beyond.
        assert_eq!(b.take(2.0, 200.0), (true, 0.0));
        assert_eq!(b.take(2.0, 200.0), (true, 0.0));
        assert!(!b.take(2.0, 200.0).0);
    }

    #[test]
    fn fractional_below_one_allows_first_then_refills() {
        // Burst=max(0.5,1)=1, refill 0.5/s: first succeeds, then 2s cadence.
        // Legacy burst=0.5 never allowed; that defect is not preserved.
        let mut b = Bucket::new(0.5, 0.0);
        assert_eq!(b.take(0.5, 0.0), (true, 0.0));
        assert_eq!(b.tokens(), 0.0);
        // Immediate: tokens 0, retry (1-0)/0.5*1000=2000.
        let (ok, retry) = b.take(0.5, 0.0);
        assert!(!ok);
        assert!((retry - 2000.0).abs() < 1e-9, "{retry}");
        // +1s refills 0.5: still short, retry (1-0.5)/0.5*1000=1000.
        let (ok, retry) = b.take(0.5, 1.0);
        assert!(!ok);
        assert!((retry - 1000.0).abs() < 1e-9, "{retry}");
        // Just before +2s: 0.9995 tokens, still short.
        assert!(!b.take(0.5, 1.999).0);
        // At +2s from first spend (last moved to 1.999, refill 0.001*0.5
        // tops up to 1.0): allowed. Use a fresh bucket for exact boundary.
        let mut c = Bucket::new(0.5, 0.0);
        assert_eq!(c.take(0.5, 0.0), (true, 0.0));
        assert!(!c.take(0.5, 1.999).0);
        // Fresh boundary: spend at 0, deny at 0, allow at exactly 2.0.
        let mut d = Bucket::new(0.5, 0.0);
        assert_eq!(d.take(0.5, 0.0), (true, 0.0));
        let (ok, _) = d.take(0.5, 0.0);
        assert!(!ok);
        assert_eq!(d.take(0.5, 2.0), (true, 0.0));
    }

    #[test]
    fn policy_increase_does_not_fabricate_old_credit() {
        // 1/s bucket spent at 0, then 10/s policy at +0.5s: elapsed
        // refills at min(1,10)=1 (0.5 tokens), so denies. Legacy
        // refills at new 10 (5 tokens) and would allow.
        let mut b = Bucket::new(1.0, 0.0);
        assert_eq!(b.take(1.0, 0.0), (true, 0.0));
        let (ok, retry) = b.take(10.0, 0.5);
        assert!(!ok, "must not fabricate 0.5s at 10/s");
        assert!((retry - 50.0).abs() < 1e-9, "{retry}");
        assert_eq!(b.per_s(), 10.0);
        // 0.05s later at 10/s refills 0.5 more: allows.
        assert_eq!(b.take(10.0, 0.55), (true, 0.0));
    }

    #[test]
    fn policy_reduction_caps_without_over_burst_or_lockout() {
        // 10/s bucket with 9 tokens left, then 1/s policy: caps at new
        // burst 1, allows once, then denies (no 9-deep over-burst).
        let mut b = Bucket::new(10.0, 0.0);
        assert_eq!(b.take(10.0, 0.0), (true, 0.0));
        assert_eq!(b.tokens(), 9.0);
        assert_eq!(b.take(1.0, 0.0), (true, 0.0));
        assert_eq!(b.tokens(), 0.0);
        assert!(!b.take(1.0, 0.0).0);
        // Exhausted 10/s bucket, then 1/s at +0.5s: min refill 0.5,
        // denies (no over-burst from old fast credit).
        let mut c = Bucket::new(10.0, 0.0);
        for _ in 0..10 {
            assert_eq!(c.take(10.0, 0.0), (true, 0.0));
        }
        assert!(!c.take(1.0, 0.5).0);
        // Slow bucket never locks out after speeding up: 0.5/s spent,
        // then 2/s refills to allow.
        let mut d = Bucket::new(0.5, 0.0);
        assert_eq!(d.take(0.5, 0.0), (true, 0.0));
        assert!(!d.take(2.0, 0.0).0);
        assert_eq!(d.take(2.0, 0.5), (true, 0.0));
    }

    #[test]
    fn tiny_rates_refuse_without_nonfinite_hints() {
        // Smallest retry-finite boundary: 1000/per_s must stay finite.
        assert!(parse_rate_value(&json!(1e-305), "r").is_ok());
        let tiny = parse_rate_value(&json!(1e-305), "r").unwrap();
        assert!((1000.0 / tiny).is_finite());
        // Too small: retry would be inf, so refuse at load.
        for v in [json!(1e-306), json!(1e-310), json!(5e-324)] {
            let err = parse_rate_value(&v, "rate_per_s").expect_err("must refuse");
            assert!(err.contains("finite retry"), "{err}");
        }
        // Allowed very small rate still yields finite hints and allows first.
        let mut b = Bucket::new(1e-3, 0.0);
        assert_eq!(b.take(1e-3, 0.0), (true, 0.0));
        let (ok, retry) = b.take(1e-3, 0.0);
        assert!(!ok);
        assert!(retry.is_finite(), "{retry}");
        assert!((retry - 1_000_000.0).abs() < 1e-3, "{retry}");
    }

    #[test]
    fn backwards_clock_with_fractional_clamps_and_caps() {
        let mut b = Bucket::new(0.5, 100.0);
        assert_eq!(b.take(0.5, 100.0), (true, 0.0));
        // Backwards: no refill, last stays, still adopts rate/cap.
        let (ok, retry) = b.take(0.5, 90.0);
        assert!(!ok);
        assert!((retry - 2000.0).abs() < 1e-9, "{retry}");
        assert_eq!(b.tokens(), 0.0);
        assert_eq!(b.last(), 100.0);
        // Forward 2s from 100: refills 1.0, allowed.
        assert_eq!(b.take(0.5, 102.0), (true, 0.0));
    }

    #[test]
    fn backwards_clock_clamps_without_drain_or_rewind() {
        let mut b = Bucket::new(1.0, 100.0);
        assert_eq!(b.take(1.0, 100.0), (true, 0.0));
        assert_eq!(b.tokens(), 0.0);
        assert_eq!(b.last(), 100.0);
        // Backwards 10s: no refill, no drain, last stays 100.
        let (ok, retry) = b.take(1.0, 90.0);
        assert!(!ok);
        assert!((retry - 1000.0).abs() < 1e-9, "{retry}");
        assert_eq!(b.tokens(), 0.0);
        assert_eq!(b.last(), 100.0);
        // Forward 1s from 100 (not 90): refills exactly 1.0, allowed.
        assert_eq!(b.take(1.0, 101.0), (true, 0.0));
    }

    #[test]
    fn malformed_values_reject_explicitly() {
        for (v, field) in [
            (json!(0), "rate_per_s"),
            (json!(0.0), "rate_per_s"),
            (json!(-1), "rate_per_s"),
            (json!(-0.5), "rate_per_s"),
            (json!("2"), "rate_per_s"),
            (json!(true), "rate_per_s"),
            (json!(false), "rate_per_s"),
            (json!([]), "rate_per_s"),
            (json!({}), "rate_per_s"),
        ] {
            assert!(parse_rate_value(&v, field).is_err(), "{v}");
        }
        assert_eq!(parse_rate_value(&json!(2), "r").unwrap(), 2.0);
        assert_eq!(parse_rate_value(&json!(0.5), "r").unwrap(), 0.5);
        assert_eq!(parse_global(None).unwrap(), None);
        assert_eq!(parse_global(Some(&Value::Null)).unwrap(), None);
        // Note: JSON text like `1e1000` never reaches here: serde_json
        // rejects it at parse (`number out of range`, BadRoot). The
        // `is_finite` guard above is defense-in-depth for programmatic
        // `Value`s (which `Value::from(inf)` collapses to null anyway).
    }

    #[test]
    fn topic_rates_falsy_means_no_rules_truthy_non_object_rejects() {
        for v in [json!(0), json!(false), json!(""), json!([]), json!({})] {
            let rules = parse_topic_rates_from_value(Some(&v)).unwrap();
            assert!(rules.is_empty(), "{v}");
        }
        assert!(parse_topic_rates_from_value(None).unwrap().is_empty());
        for v in [json!([1]), json!("x"), json!(5), json!(true)] {
            assert!(parse_topic_rates_from_value(Some(&v)).is_err(), "{v}");
        }
    }

    #[test]
    fn first_match_wins_else_global() {
        let cfg = RateConfig {
            global: Some(10.0),
            rules: parse_rules_ordered(vec![
                ("board.*".to_string(), json!(5)),
                ("board.build".to_string(), json!(1)),
            ])
            .unwrap(),
        };
        // First pattern wins even though the second is more specific.
        assert_eq!(cfg.select("board.build"), Some(("board.*", 5.0)));
        assert_eq!(cfg.select("board.other"), Some(("board.*", 5.0)));
        assert_eq!(cfg.select("inbox.a"), Some(("*", 10.0)));
        let unlimited = RateConfig::default();
        assert_eq!(unlimited.select("board.build"), None);
    }

    #[test]
    fn limiter_shares_per_agent_and_rule() {
        let mut lim = RateLimiter::new();
        assert!(lim.is_empty());
        // Agent alice, rule board.*: burst 1.
        assert_eq!(lim.check("alice", "board.*", 1.0, 0.0), (true, 0.0));
        assert!(!lim.check("alice", "board.*", 1.0, 0.0).0);
        // Same agent, different rule: separate bucket.
        assert_eq!(lim.check("alice", "*", 1.0, 0.0), (true, 0.0));
        // Different agent, same rule: separate bucket.
        assert_eq!(lim.check("bob", "board.*", 1.0, 0.0), (true, 0.0));
        assert_eq!(lim.len(), 3);
        // Refill after 1s: shared bucket allows again.
        assert_eq!(lim.check("alice", "board.*", 1.0, 1.0), (true, 0.0));
    }
}

//! Pure ACL/token-grant core: authenticated names, publish/subscribe,
//! KV grants, and deterministic wildcard matching.
//!
//! Native port of the transitional Python broker's authorization policy
//! (`broker.py` `name_allowed`/`covers`/`can_pub`/`can_sub`/`kv_lists`/
//! `can_kv`/`can_kv_list`, plus the `hello` expiry/name checks and the
//! `fetch` exactness guard, read as text only), without any wire,
//! broker, filesystem, network, or environment interaction. This module
//! owns grant shapes, validation, matching, and pre-cap filtering
//! predicates. Wire integration stays with the builder-owned `wire.rs`
//! and KV state stays with `kv.rs`.
//!
//! Preserved contract (see `docs/NATIVE_ACL_MIGRATION.md`):
//! - Authenticated names: exact `agent`, admin `"*"` (any name), or
//!   `claim` glob. Empty `claimed` is rejected by [`TokenStore::authenticate`]
//!   (`"auth failed"`), matching `hello`; bare [`Policy::name_allowed`]
//!   preserves `name_allowed` exactly (admin matches even empty).
//! - Publish: any `publish` glob matches the topic via fnmatch-compatible
//!   wildcards. Empty topics are denied before matching, matching
//!   `if not topic or not can_pub`.
//! - Subscribe/fetch/topics: conservative [`covers`] (exact, `"*"`, or
//!   trailing-`"*" prefix only). `?`/`[` are literal to `covers`.
//!   [`Policy::can_fetch`] additionally rejects topics containing
//!   `*?[` (exactly those three, matching the legacy guard).
//! - KV: `kv_read`/`kv_write` missing or JSON null fall back to
//!   `subscribe`/`publish` grants; an explicit empty list denies.
//!   Per-key checks use wildcard matching; `kv_list` prefix checks use
//!   [`covers`] over the effective `kv_read` set. [`Policy::topic_visible`]
//!   and [`Policy::kv_key_visible`] are predicates the broker applies
//!   before any list cap, matching legacy `[... if allowed][:1000]`.
//! - Expiry: a token is expired exactly when `now > exp`; at
//!   `now == exp` it is still live, matching `hello`.
//!
//! Wildcard syntax (fnmatch-compatible subset, Unicode scalar based):
//! - `*` matches any (possibly empty) char sequence, including `.`.
//! - `?` matches exactly one Unicode scalar value.
//! - `[seq]` matches exactly one char in `seq`; `[!seq]` matches one
//!   char not in `seq`. Only leading `!` negates (`^` is literal).
//!   A leading `]` is a literal member (so `[]]` matches `]`).
//!   `-` between two members denotes an inclusive range by scalar
//!   value (`[a-z]`); otherwise it is literal. Chained/overlapping
//!   ranges like `[a-b-c]` or `[0-9-a-z]` are rejected as ambiguous
//!   rather than widened. `\` is literal (no escapes). Matching is
//!   case-sensitive, iterative (no recursion, no exponential
//!   backtracking), and operates on `char`s, not bytes.
//! - Malformed patterns are rejected at configuration time
//!   ([`Pattern::new`] returns [`AclError::BadPattern`]): unterminated
//!   `[`, empty `[]`/`[!]`, reversed ranges like `[z-a]`, and
//!   overlapping/chained ranges like `[a-b-c]`. Legacy `fnmatch`
//!   treats unterminated brackets literally and (in 3.12 `translate`)
//!   removes reversed ranges (yielding a reduced set or never-match,
//!   not a crash); native rejects explicitly rather than widening or
//!   silently narrowing grants. See the migration doc for the table.
//!
//! Strict validation, no secret echo:
//! - Token roots must be JSON objects; non-object entries are preserved
//!   as `meta` (matching `load_tokens`). Entry indices in
//!   [`AclError::BadEntry`] count token (object) entries in sorted-key
//!   (`BTreeMap`) order; token strings never appear in any
//!   `Display`/`Debug`.
//! - Grant types are validated: `publish`/`subscribe` must be missing
//!   (deny) or a list of strings (null and non-lists rejected, since
//!   legacy would crash); `kv_read`/`kv_write` may additionally be
//!   null (fallback); `agent`/`claim` must be missing/null or strings;
//!   `exp` must be missing/null or a finite number. Unknown fields are
//!   preserved in [`Policy::extra`] for later integration.
//! - Rate configs are validated here (ordered, fail-closed) for wire
//!   enforcement via `crate::rate`: `rate_per_s` and every
//!   `topic_rates` value must be a finite number `> 0`, patterns must
//!   be valid [`Pattern`]s, truthy non-object `topic_rates` rejects.
//!   Raw values stay in [`Policy::extra`] for `limits` echo; the
//!   validated first-match view lives in [`Policy::rate_config`].
//!   Artifact quotas and token mutations stay explicitly unimplemented:
//!   [`Policy::enforce_artifact_quota`] and
//!   [`Policy::enforce_token_admin`] (plus [`Policy::enforce_rate_limit`]
//!   for ACL-only callers, since buckets live in `wire`) always return
//!   [`AclError::Unsupported`]. Never assume `extra` is enforced.
//!
//! No IO is performed: all inputs are caller-provided `&str`/`&Value`/
//! `f64` time, and all outputs are pure decisions or preserved data.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::rate::RateConfig;

/// Validation/authorization failure. Token strings never appear in any
/// variant: [`AclError::BadEntry`] reports the token-entry index in
/// sorted-key order, and auth failures are unit variants with the legacy
/// messages (`"auth failed"`, `"token expired"`, `"agent/token mismatch"`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AclError {
    /// Token root is not a JSON object, or is not valid JSON.
    BadRoot(String),
    /// Single policy value is not an object or has a malformed field.
    /// Used by [`Policy::from_json`]; [`TokenStore`] wraps the same
    /// reason as [`AclError::BadEntry`] with the entry index.
    BadPolicy(String),
    /// Token entry `index` (0-based among object entries in sorted-key
    /// order) has a malformed field. `reason` never contains the token.
    BadEntry {
        index: usize,
        reason: String,
    },
    /// Glob pattern has unsupported syntax (unterminated bracket,
    /// empty class, reversed or overlapping range). Contains the
    /// pattern and position for debuggability; patterns are policy,
    /// not secrets.
    BadPattern(String),
    /// Explicitly unimplemented enforcement (artifact quotas, token
    /// mutations, plus rate checks for ACL-only callers whose buckets
    /// live in `wire`). The policy value is preserved in
    /// [`Policy::extra`]; never treat this as allowed.
    Unsupported(String),
    /// Unknown token, or empty claimed name. Matches `hello`.
    AuthFailed,
    /// Token `exp` has passed (`now > exp`).
    TokenExpired,
    /// Claimed name matches neither `agent` nor `claim`.
    AgentMismatch,
    /// Auth clock `now` was non-finite (NaN/±inf). Rejected before any
    /// expiry/name checks, matching `kv::NonFiniteTime`.
    NonFiniteTime,
}

impl std::fmt::Display for AclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AclError::BadRoot(detail) => write!(f, "bad token root: {detail}"),
            AclError::BadPolicy(detail) => write!(f, "bad policy: {detail}"),
            AclError::BadEntry { index, reason } => {
                write!(f, "bad token entry {index}: {reason}")
            }
            AclError::BadPattern(detail) => write!(f, "bad pattern: {detail}"),
            AclError::Unsupported(detail) => write!(f, "unsupported: {detail}"),
            AclError::AuthFailed => write!(f, "auth failed"),
            AclError::TokenExpired => write!(f, "token expired"),
            AclError::AgentMismatch => write!(f, "agent/token mismatch"),
            AclError::NonFiniteTime => write!(f, "non-finite time"),
        }
    }
}

impl std::error::Error for AclError {}

// ---------------------------------------------------------------------------
// Wildcard patterns
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum ClassMember {
    Single(char),
    Range(char, char),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClassMatcher {
    negated: bool,
    members: Vec<ClassMember>,
}

impl ClassMatcher {
    fn matches(&self, c: char) -> bool {
        let hit = self.members.iter().any(|m| match m {
            ClassMember::Single(s) => *s == c,
            ClassMember::Range(lo, hi) => *lo <= c && c <= *hi,
        });
        if self.negated { !hit } else { hit }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PatternToken {
    Star,
    Question,
    Literal(char),
    Class(ClassMatcher),
}

/// A validated glob pattern. Construct with [`Pattern::new`], which
/// rejects unsupported bracket syntax explicitly instead of matching
/// it literally. Matching is iterative over Unicode scalars.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    raw: String,
    tokens: Vec<PatternToken>,
}

impl Pattern {
    /// Validate `raw` and pre-parse it. Accepts any string, including
    /// empty (which matches only empty text); rejects unterminated
    /// `[`, empty classes, reversed ranges, and overlapping/chained
    /// ranges.
    pub fn new(raw: &str) -> Result<Self, AclError> {
        let tokens = parse_pattern(raw).map_err(AclError::BadPattern)?;
        Ok(Pattern { raw: raw.to_string(), tokens })
    }

    /// The original pattern text.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// True when `text` matches this (already validated) pattern.
    /// Infallible: validation happened at construction.
    pub fn matches(&self, text: &str) -> bool {
        match_tokens(text, &self.tokens)
    }
}

/// Validate `pattern` then match `text` against it. Prefer
/// [`Pattern::new`] plus [`Pattern::matches`] when matching repeatedly.
pub fn wildcard_match(text: &str, pattern: &str) -> Result<bool, AclError> {
    Ok(Pattern::new(pattern)?.matches(text))
}

fn parse_pattern(raw: &str) -> Result<Vec<PatternToken>, String> {
    let chars: Vec<char> = raw.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                // Collapse runs: `**` == `*`.
                if !matches!(tokens.last(), Some(PatternToken::Star)) {
                    tokens.push(PatternToken::Star);
                }
                i += 1;
            }
            '?' => {
                tokens.push(PatternToken::Question);
                i += 1;
            }
            '[' => {
                let (class, next) = parse_class(&chars, i, raw)?;
                tokens.push(PatternToken::Class(class));
                i = next;
            }
            c => {
                tokens.push(PatternToken::Literal(c));
                i += 1;
            }
        }
    }
    Ok(tokens)
}

fn parse_class(chars: &[char], start: usize, raw: &str) -> Result<(ClassMatcher, usize), String> {
    // chars[start] == '['.
    let mut i = start + 1;
    if i >= chars.len() {
        return Err(format!("{raw:?}: unterminated '[' at char {start}"));
    }
    let negated = if chars[i] == '!' {
        i += 1;
        if i >= chars.len() {
            return Err(format!("{raw:?}: unterminated '[' at char {start}"));
        }
        true
    } else {
        false
    };
    // A leading ']' is a literal member, not the closer (so `[]]`
    // matches `]` and `[!]]` matches any char except `]`).
    let has_leading_bracket = i < chars.len() && chars[i] == ']';
    if has_leading_bracket {
        i += 1;
    }
    // Find the closer from here.
    let mut close = None;
    for (offset, c) in chars.iter().enumerate().skip(i) {
        if *c == ']' {
            close = Some(offset);
            break;
        }
    }
    let close = match close {
        Some(c) => c,
        None => return Err(format!("{raw:?}: unterminated '[' at char {start}")),
    };
    // Full member content between the outer brackets, excluding the
    // optional leading `!` but including a leading `]` if present.
    let content_start = start + 1 + usize::from(negated);
    let content: Vec<char> = chars[content_start..close].to_vec();
    if content.is_empty() {
        return Err(format!("{raw:?}: empty '[]' at char {start}"));
    }
    let members = parse_class_members(&content, raw, start)?;
    Ok((ClassMatcher { negated, members }, close + 1))
}

fn parse_class_members(content: &[char], raw: &str, start: usize) -> Result<Vec<ClassMember>, String> {
    let mut members = Vec::new();
    let mut j = 0;
    while j < content.len() {
        if content[j] == '-' && j > 0 && j + 1 < content.len() {
            let prev = content[j - 1];
            let next = content[j + 1];
            if prev > next {
                return Err(format!(
                    "{raw:?}: reversed range '{prev}-{next}' at char {start}"
                ));
            }
            // Reject chained/overlapping ranges like `[a-b-c]` or
            // `[0-9-a-z]`: `prev` is already the end of the previous
            // range, so a second range would widen beyond legacy
            // (which escapes the later `-` literally via its chunk
            // join). Legacy supports single ranges plus literal `-`.
            if matches!(members.last(), Some(ClassMember::Range(_, end)) if *end == prev) {
                return Err(format!(
                    "{raw:?}: overlapping range '{prev}-{next}' at char {start}"
                ));
            }
            // `prev` was already pushed as a single; replace it with
            // the range.
            if matches!(members.last(), Some(ClassMember::Single(s)) if *s == prev) {
                members.pop();
            }
            members.push(ClassMember::Range(prev, next));
            j += 2; // Skip '-' and the range end (consumed).
        } else {
            members.push(ClassMember::Single(content[j]));
            j += 1;
        }
    }
    if members.is_empty() {
        return Err(format!("{raw:?}: empty '[]' at char {start}"));
    }
    Ok(members)
}

fn token_matches_single(token: &PatternToken, c: char) -> bool {
    match token {
        PatternToken::Star => false, // Handled separately in the loop.
        PatternToken::Question => true,
        PatternToken::Literal(l) => *l == c,
        PatternToken::Class(m) => m.matches(c),
    }
}

/// Iterative star-backtracking match over Unicode scalars. No recursion;
/// worst case is quadratic (pattern stars x text length), never
/// exponential, and deterministic.
fn match_tokens(text: &str, tokens: &[PatternToken]) -> bool {
    let text: Vec<char> = text.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_match = 0usize;
    while ti < text.len() {
        if pi < tokens.len() && token_matches_single(&tokens[pi], text[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < tokens.len() && matches!(tokens[pi], PatternToken::Star) {
            star = Some(pi);
            star_match = ti;
            pi += 1;
        } else if let Some(star_pi) = star {
            star_match += 1;
            ti = star_match;
            pi = star_pi + 1;
        } else {
            return false;
        }
    }
    while pi < tokens.len() && matches!(tokens[pi], PatternToken::Star) {
        pi += 1;
    }
    pi == tokens.len()
}

/// Conservative subscription coverage, exactly matching legacy `covers`:
/// `"*"` covers everything; a grant without `*` covers only itself;
/// a grant ending in `*` covers the literal prefix; any other grant
/// containing `*` covers nothing. `?` and `[` are literal here (they
/// only gain meaning in [`Pattern`] matching for publish/KV checks).
pub fn covers(requested: &str, allowed: &str) -> bool {
    if allowed == "*" {
        return true;
    }
    if !allowed.contains('*') {
        return requested == allowed;
    }
    if let Some(prefix) = allowed.strip_suffix('*') {
        return requested.starts_with(prefix);
    }
    false
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

const KNOWN_FIELDS: [&str; 7] =
    ["agent", "claim", "publish", "subscribe", "kv_read", "kv_write", "exp"];

/// One validated token entry: enforced identity/expiry/grant fields,
/// validated rate config for wire enforcement, plus preserved unknown
/// fields. No token secret is stored here; see [`TokenStore`] for the
/// secret-keyed map with redacted diagnostics.
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    agent: Option<String>,
    claim: Option<Pattern>,
    publish: Vec<Pattern>,
    subscribe: Vec<Pattern>,
    kv_read: Option<Vec<Pattern>>,
    kv_write: Option<Vec<Pattern>>,
    exp: Option<f64>,
    extra: BTreeMap<String, Value>,
    rate: RateConfig,
}

impl Policy {
    /// Validate one token-entry object. Missing `publish`/`subscribe`
    /// mean deny (empty); explicit null is rejected (legacy would
    /// crash iterating it). Missing/null `kv_read`/`kv_write` mean
    /// fallback (see [`Policy::effective_kv_read`]); explicit lists
    /// (even empty) are honored. Unknown members are preserved in
    /// [`Policy::extra`]. Rate members (`rate_per_s`/`topic_rates`) are
    /// validated into [`Policy::rate_config`] (sorted-order rules here;
    /// [`TokenStore::from_json_str`] replaces them with file order and wire
    /// issue replaces them with request-document order via
    /// [`Policy::with_ordered_topic_rates`]).
    pub fn from_json(value: &Value) -> Result<Self, AclError> {
        from_object(value).map_err(AclError::BadPolicy)
    }

    /// Bound identity, or `None` when missing/null. `"*"` is admin.
    pub fn agent(&self) -> Option<&str> {
        self.agent.as_deref()
    }

    /// Validated `claim` glob, or `None` when missing/null.
    pub fn claim_pattern(&self) -> Option<&Pattern> {
        self.claim.as_ref()
    }

    /// Validated `publish` grants (missing means empty/deny).
    pub fn publish_grants(&self) -> &[Pattern] {
        &self.publish
    }

    /// Validated `subscribe` grants (missing means empty/deny).
    pub fn subscribe_grants(&self) -> &[Pattern] {
        &self.subscribe
    }

    /// Explicit `kv_read` grants, or `None` for missing/null (fallback).
    pub fn kv_read_grants(&self) -> Option<&[Pattern]> {
        self.kv_read.as_deref()
    }

    /// Explicit `kv_write` grants, or `None` for missing/null (fallback).
    pub fn kv_write_grants(&self) -> Option<&[Pattern]> {
        self.kv_write.as_deref()
    }

    /// Effective `kv_read` set: explicit grants, else `subscribe`
    /// (legacy `kv_lists` fallback for missing/null).
    pub fn effective_kv_read(&self) -> &[Pattern] {
        self.kv_read.as_deref().unwrap_or(&self.subscribe)
    }

    /// Effective `kv_write` set: explicit grants, else `publish`.
    pub fn effective_kv_write(&self) -> &[Pattern] {
        self.kv_write.as_deref().unwrap_or(&self.publish)
    }

    /// Absolute unix-seconds expiry, or `None` for no expiry.
    pub fn exp(&self) -> Option<f64> {
        self.exp
    }

    /// Preserved unknown policy members (rate/artifact/custom), never
    /// enforced here. Rate raw values stay here for `limits` echo; the
    /// validated first-match view is [`Policy::rate_config`]. See the
    /// `enforce_*` methods.
    pub fn extra(&self) -> &BTreeMap<String, Value> {
        &self.extra
    }

    /// Validated rate policy for wire enforcement (ordered first-match
    /// rules plus global fallback). File order for text loads, wire-document
    /// order for issue requests via [`Policy::with_ordered_topic_rates`],
    /// sorted order for bare [`Policy::from_json`] `Value` inputs.
    pub fn rate_config(&self) -> &RateConfig {
        &self.rate
    }

    /// Replace topic-rate rules with request-document order (wire issue path).
    /// Validates `ordered` pairs (duplicate collapse last-value-first-position
    /// inside `parse_rules_ordered`) and swaps them in, preserving global and
    /// all other fields. Fails closed on any validation error with the same
    /// `topic_rates[...]` reason [`Policy::from_json`] would give (caller wraps
    /// as `BadPolicy`). Callers must have already validated the base policy via
    /// `from_json` (so grants/exp/global are known good); this only re-validates
    /// topic rules in true first-match order. Use only with pairs parsed from
    /// the raw wire line in document order; sorted `Value` inputs have no
    /// document order.
    pub fn with_ordered_topic_rates(mut self, ordered: Vec<(String, Value)>) -> Result<Self, String> {
        let rules = crate::rate::parse_rules_ordered(ordered)?;
        self.rate.rules = rules;
        Ok(self)
    }

    /// True exactly when `now > exp`, mirroring `hello`. `None` never
    /// expires; `now == exp` is still live. Direct callers must pass a
    /// finite `now` (non-finite follows plain float comparison and is
    /// a logic error, matching `kv::expired`);
    /// [`TokenStore::authenticate`] rejects non-finite clocks as
    /// [`AclError::NonFiniteTime`].
    pub fn is_expired(&self, now: f64) -> bool {
        matches!(self.exp, Some(e) if now > e)
    }

    /// May this policy claim `claimed`? Exactly `name_allowed`: admin
    /// `"*"` allows any name, exact `agent` allows itself, otherwise a
    /// non-empty `claim` glob must match. Empty `claimed` is allowed
    /// here for admin (matching the bare function);
    /// [`TokenStore::authenticate`] rejects it as `"auth failed"`,
    /// matching `hello`.
    pub fn name_allowed(&self, claimed: &str) -> bool {
        if self.agent.as_deref() == Some("*") {
            return true;
        }
        if let Some(agent) = &self.agent {
            if claimed == agent {
                return true;
            }
        }
        match &self.claim {
            Some(pat) if !pat.as_str().is_empty() => pat.matches(claimed),
            _ => false,
        }
    }

    /// May this policy publish to `topic`? False for empty topics,
    /// else any `publish` glob matches. Mirrors
    /// `if not topic or not can_pub`.
    pub fn can_publish(&self, topic: &str) -> bool {
        if topic.is_empty() {
            return false;
        }
        self.publish.iter().any(|p| p.matches(topic))
    }

    /// May this policy subscribe to `pattern`? False for empty
    /// patterns, else any `subscribe` grant [`covers`] it. Mirrors
    /// `if not pattern or not can_sub`.
    pub fn can_subscribe(&self, pattern: &str) -> bool {
        if pattern.is_empty() {
            return false;
        }
        self.subscribe.iter().any(|a| covers(pattern, a.as_str()))
    }

    /// May this policy fetch exact `topic` history? False for empty
    /// topics, topics containing `*?[` (exactly those three, matching
    /// the legacy guard), or topics no `subscribe` grant [`covers`].
    pub fn can_fetch(&self, topic: &str) -> bool {
        if topic.is_empty() || topic.chars().any(|c| c == '*' || c == '?' || c == '[') {
            return false;
        }
        self.can_subscribe(topic)
    }

    /// May this policy read KV `key`? Any effective-`kv_read` glob
    /// matches. Pure matching (no empty-key rule; that stays with
    /// `kv::KvStore` for puts/deletes).
    pub fn can_kv_read(&self, key: &str) -> bool {
        self.effective_kv_read().iter().any(|p| p.matches(key))
    }

    /// May this policy write KV `key`? Any effective-`kv_write` glob
    /// matches. Pure matching.
    pub fn can_kv_write(&self, key: &str) -> bool {
        self.effective_kv_write().iter().any(|p| p.matches(key))
    }

    /// May this policy list KV under `prefix`? Any effective-`kv_read`
    /// grant [`covers`] the prefix. Empty prefixes are usually denied
    /// for scoped grants (e.g. `""` is not covered by `"bus.*"`),
    /// matching legacy `can_kv_list`.
    pub fn can_kv_list(&self, prefix: &str) -> bool {
        self.effective_kv_read().iter().any(|a| covers(prefix, a.as_str()))
    }

    /// Is `topic` visible in a `topics` listing? Any `subscribe` grant
    /// [`covers`] it. Pure predicate for pre-cap filtering.
    pub fn topic_visible(&self, topic: &str) -> bool {
        self.subscribe.iter().any(|a| covers(topic, a.as_str()))
    }

    /// Is KV `key` visible in a `kv_list` result? Same as
    /// [`Policy::can_kv_read`]; named for pre-cap filtering clarity.
    pub fn kv_key_visible(&self, key: &str) -> bool {
        self.can_kv_read(key)
    }

    /// Filter `topics` to visible ones, preserving input order. Apply
    /// before any result cap.
    pub fn filter_topics<'a>(&self, topics: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
        topics.into_iter().filter(|t| self.topic_visible(t)).collect()
    }

    /// Filter `keys` to readable ones, preserving input order. Apply
    /// before the 1000-cap, matching legacy `[... if allowed][:1000]`.
    pub fn filter_keys<'a>(&self, keys: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
        keys.into_iter().filter(|k| self.kv_key_visible(k)).collect()
    }

    /// Rate buckets live in `wire` (stateful, clocked), so ACL-only
    /// callers always get [`AclError::Unsupported`] here. Wire
    /// enforcement reads the validated [`Policy::rate_config`]; the raw
    /// `rate_per_s`/`topic_rates` policy (if any) stays in
    /// [`Policy::extra`] for `limits` echo.
    pub fn enforce_rate_limit(&self, _topic: &str) -> Result<(), AclError> {
        Err(AclError::Unsupported(
            "rate limits enforced in wire via rate config".to_string(),
        ))
    }

    /// Artifact quotas are not implemented here. Always returns
    /// [`AclError::Unsupported`]; the raw `art_quota_bytes` policy (if
    /// any) is preserved in [`Policy::extra`].
    pub fn enforce_artifact_quota(&self, _bytes: u64) -> Result<(), AclError> {
        Err(AclError::Unsupported(
            "artifact quotas not implemented in native ACL".to_string(),
        ))
    }

    /// Token issue/revoke/claim mutations are not implemented here.
    /// Always returns [`AclError::Unsupported`].
    pub fn enforce_token_admin(&self) -> Result<(), AclError> {
        Err(AclError::Unsupported(
            "token mutations not implemented in native ACL".to_string(),
        ))
    }
}

fn from_object(value: &Value) -> Result<Policy, String> {
    let obj = value.as_object().ok_or_else(|| "policy must be an object".to_string())?;
    let agent = parse_optional_string(obj, "agent")?;
    let claim_raw = parse_optional_string(obj, "claim")?;
    let claim = match claim_raw {
        None => None,
        Some(s) => Some(
            Pattern::new(&s).map_err(|e| format!("claim: {e}"))?,
        ),
    };
    let publish = parse_required_grants(obj, "publish")?;
    let subscribe = parse_required_grants(obj, "subscribe")?;
    let kv_read = parse_optional_grants(obj, "kv_read")?;
    let kv_write = parse_optional_grants(obj, "kv_write")?;
    let exp = parse_optional_exp(obj)?;
    // Validated rate view for wire enforcement (sorted-order rules here;
    // text loads replace them with file order). Raw values also stay in
    // `extra` below for `limits` echo. Malformed rates fail closed.
    let global = crate::rate::parse_global(obj.get("rate_per_s"))?;
    let rules = crate::rate::parse_topic_rates_from_value(obj.get("topic_rates"))?;
    let rate = RateConfig { global, rules };
    let mut extra = BTreeMap::new();
    for (k, v) in obj {
        if !KNOWN_FIELDS.contains(&k.as_str()) {
            extra.insert(k.clone(), v.clone());
        }
    }
    Ok(Policy { agent, claim, publish, subscribe, kv_read, kv_write, exp, extra, rate })
}

fn parse_optional_string(
    obj: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<String>, String> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("{field} must be a string")),
    }
}

/// Missing means empty/deny; explicit null or a non-list is malformed
/// (legacy would crash iterating it, so native rejects explicitly).
fn parse_required_grants(
    obj: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Vec<Pattern>, String> {
    match obj.get(field) {
        None => Ok(Vec::new()),
        Some(Value::Null) => Err(format!("{field} must be a list (got null)")),
        Some(Value::Array(items)) => parse_grant_list(items, field),
        Some(_) => Err(format!("{field} must be a list")),
    }
}

/// Missing/null mean fallback (`None`); otherwise an explicit list
/// (possibly empty, which denies).
fn parse_optional_grants(
    obj: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<Vec<Pattern>>, String> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => Ok(Some(parse_grant_list(items, field)?)),
        Some(_) => Err(format!("{field} must be a list")),
    }
}

fn parse_grant_list(items: &[Value], field: &str) -> Result<Vec<Pattern>, String> {
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| format!("{field}[{i}] must be a string"))?;
        out.push(Pattern::new(s).map_err(|e| format!("{field}[{i}]: {e}"))?);
    }
    Ok(out)
}

fn parse_optional_exp(obj: &serde_json::Map<String, Value>) -> Result<Option<f64>, String> {
    match obj.get("exp") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let e = v.as_f64().ok_or_else(|| "exp must be a number".to_string())?;
            if !e.is_finite() {
                return Err("exp must be finite".to_string());
            }
            Ok(Some(e))
        }
    }
}

// ---------------------------------------------------------------------------
// Token store
// ---------------------------------------------------------------------------

/// Validated token database: secret-keyed policies plus preserved
/// non-object `meta` (matching `load_tokens`). `Debug` shows counts
/// only for both maps (no token strings, meta keys, or meta values);
/// no error variant echoes a token.
#[derive(Clone, PartialEq)]
pub struct TokenStore {
    entries: BTreeMap<String, Policy>,
    meta: BTreeMap<String, Value>,
}

impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenStore")
            .field("entries", &self.entries.len())
            .field("meta", &self.meta.len())
            .finish()
    }
}

impl TokenStore {
    /// Validate a parsed `tokens.json` root. Object values are token
    /// entries; non-object values are preserved as `meta`. Entry
    /// indices in [`AclError::BadEntry`] count object entries in
    /// sorted-key (`BTreeMap`) order with current serde features,
    /// never naming the token. Rate rules here are sorted-key order
    /// (the `Value` input has no file order); use
    /// [`TokenStore::from_json_str`] for file-ordered first-match.
    pub fn from_root(value: &Value) -> Result<Self, AclError> {
        let obj = value
            .as_object()
            .ok_or_else(|| AclError::BadRoot("token root must be an object".to_string()))?;
        let mut entries = BTreeMap::new();
        let mut meta = BTreeMap::new();
        let mut index = 0usize;
        for (key, val) in obj {
            if val.is_object() {
                match from_object(val) {
                    Ok(policy) => {
                        entries.insert(key.clone(), policy);
                    }
                    Err(reason) => return Err(AclError::BadEntry { index, reason }),
                }
                index += 1;
            } else {
                meta.insert(key.clone(), val.clone());
            }
        }
        Ok(TokenStore { entries, meta })
    }

    /// Parse and validate `tokens.json` text. The serde failure detail
    /// is positional only and never echoes token content. Rate rules
    /// are file-ordered first-match (a second ordered pass replaces the
    /// sorted-order rules from [`TokenStore::from_root`]).
    pub fn from_json_str(text: &str) -> Result<Self, AclError> {
        let value: Value =
            serde_json::from_str(text).map_err(|e| AclError::BadRoot(format!("invalid JSON: {e}")))?;
        let mut store = Self::from_root(&value)?;
        apply_file_ordered_rates(&mut store, text)?;
        Ok(store)
    }

    /// Number of token (object) entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when there are no token entries (meta may still exist).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Preserved non-object root members (e.g. `_note`).
    pub fn meta(&self) -> &BTreeMap<String, Value> {
        &self.meta
    }

    /// Look up the policy for `token`, if present. No validation.
    pub fn get(&self, token: &str) -> Option<&Policy> {
        self.entries.get(token)
    }

    /// Authenticate `token` claiming `claimed` at `now`, mirroring
    /// `hello`: unknown tokens and empty names fail as
    /// [`AclError::AuthFailed`], passed `exp` fails as
    /// [`AclError::TokenExpired`], and name mismatches fail as
    /// [`AclError::AgentMismatch`]. No failure echoes the token.
    /// Non-finite `now` fails as [`AclError::NonFiniteTime`] before
    /// any other check.
    pub fn authenticate(
        &self,
        token: &str,
        claimed: &str,
        now: f64,
    ) -> Result<&Policy, AclError> {
        if !now.is_finite() {
            return Err(AclError::NonFiniteTime);
        }
        if claimed.is_empty() {
            return Err(AclError::AuthFailed);
        }
        let policy = self.entries.get(token).ok_or(AclError::AuthFailed)?;
        if policy.is_expired(now) {
            return Err(AclError::TokenExpired);
        }
        if !policy.name_allowed(claimed) {
            return Err(AclError::AgentMismatch);
        }
        Ok(policy)
    }
}

// ---------------------------------------------------------------------------
// File-ordered rate second pass (text loads only)
// ---------------------------------------------------------------------------

/// Token-file entry for the ordered pass: policy objects yield
/// file-ordered `topic_rates`, non-objects are meta (skipped).
#[derive(Debug)]
enum OrderedEntry {
    Policy(crate::rate::OrderedTopicRates),
    Meta,
}

impl<'de> serde::Deserialize<'de> for OrderedEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, SeqAccess, Visitor};

        struct EntryVisitor;

        impl<'de> Visitor<'de> for EntryVisitor {
            type Value = OrderedEntry;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("token entry object or meta value")
            }

            fn visit_map<A>(self, mut map: A) -> Result<OrderedEntry, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut rates = crate::rate::OrderedTopicRates(Vec::new());
                while let Some(key) = map.next_key::<String>()? {
                    if key == "topic_rates" {
                        rates = map.next_value::<crate::rate::OrderedTopicRates>()?;
                    } else {
                        let _ = map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(OrderedEntry::Policy(rates))
            }

            fn visit_unit<E>(self) -> Result<OrderedEntry, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedEntry::Meta)
            }

            fn visit_bool<E>(self, _b: bool) -> Result<OrderedEntry, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedEntry::Meta)
            }

            fn visit_i64<E>(self, _n: i64) -> Result<OrderedEntry, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedEntry::Meta)
            }

            fn visit_u64<E>(self, _n: u64) -> Result<OrderedEntry, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedEntry::Meta)
            }

            fn visit_f64<E>(self, _f: f64) -> Result<OrderedEntry, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedEntry::Meta)
            }

            fn visit_str<E>(self, _s: &str) -> Result<OrderedEntry, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedEntry::Meta)
            }

            fn visit_string<E>(self, _s: String) -> Result<OrderedEntry, E>
            where
                E: serde::de::Error,
            {
                Ok(OrderedEntry::Meta)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<OrderedEntry, A::Error>
            where
                A: SeqAccess<'de>,
            {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(OrderedEntry::Meta)
            }
        }

        deserializer.deserialize_any(EntryVisitor)
    }
}

/// Replace sorted-order rate rules with file-ordered first-match rules.
/// Runs only after [`TokenStore::from_root`] succeeded, so all configs
/// are already valid; re-validation here is order-independent and should
/// succeed (fail-closed on any inconsistency, never echoing tokens).
fn apply_file_ordered_rates(store: &mut TokenStore, text: &str) -> Result<(), AclError> {
    let ordered: BTreeMap<String, OrderedEntry> = serde_json::from_str(text)
        .map_err(|e| AclError::BadRoot(format!("invalid JSON: {e}")))?;
    for (index, (token, policy)) in store.entries.iter_mut().enumerate() {
        match ordered.get(token) {
            Some(OrderedEntry::Policy(rates)) => {
                let rules = crate::rate::parse_rules_ordered(rates.0.clone())
                    .map_err(|reason| AclError::BadEntry { index, reason })?;
                policy.rate.rules = rules;
            }
            _ => {
                return Err(AclError::BadRoot(
                    "token entries inconsistent between parses".to_string(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_collapse_matches_empty() {
        let p = Pattern::new("**").unwrap();
        assert!(p.matches(""));
        assert!(p.matches("board.build"));
    }
}

//! Durable token-admin core: name/TTL validation, fixed defaults, secure
//! RNG, atomic file persistence, and claim-rate helpers.
//!
//! Pure validation reuses `crate::acl` (no duplicate grant/rate parser):
//! issue/claim entries are built as `serde_json::Value` and validated via
//! `Policy::from_json` / `TokenStore::from_root` by the caller (wire).
//! This module owns only the shapes legacy `broker.py` hard-codes
//! (read as text): bounded agent names, `ttl_s` → `exp`, fixed
//! least-privilege grants, `tok-{agent}-{hex8}` IDs, rolling 3/hour
//! pruning, and `tmp(0600)+fsync+rename+dir-fsync` replacement.
//!
//! No token secret ever appears in an error, `Debug`, or log. Persistence
//! errors name the operation only. RNG reads `/dev/urandom` and refuses
//! on failure (no weak or predictable fallback).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Max agent-name chars (legacy `len(wanted) > 32`).
pub const CLAIM_NAME_MAX: usize = 32;
/// Claim window seconds (legacy `now - t < 3600`).
pub const CLAIM_WINDOW_S: f64 = 3600.0;
/// Max successful claims per window per claimant (legacy `>= 3`).
pub const CLAIM_MAX: usize = 3;
/// Random bytes per token (`secrets.token_hex(8)` → 16 hex chars).
pub const TOKEN_RANDOM_BYTES: usize = 8;

/// Persistence failpoints for tests (production always `NONE`, mirroring
/// `wal::APPEND_FAIL_*`). Pre-rename modes leave the destination
/// untouched (safe retry, no poison); `DIR_FSYNC` renames then fails
/// (post-rename uncertainty, caller must poison).
pub const TOKENS_FAIL_NONE: u8 = 0;
pub const TOKENS_FAIL_TMP_WRITE: u8 = 1;
pub const TOKENS_FAIL_TMP_FSYNC: u8 = 2;
pub const TOKENS_FAIL_RENAME: u8 = 3;
pub const TOKENS_FAIL_DIR_FSYNC: u8 = 4;

/// Atomic-persist failure. `message` names the operation only (never a
/// token). `post_rename_uncertain` is true only when the rename may have
/// happened (dir-fsync failure): the destination is uncertain and the
/// caller must poison further token mutations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistError {
    pub message: String,
    pub post_rename_uncertain: bool,
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PersistError {}

/// Bounded valid agent name, exactly legacy
/// `^[A-Za-z0-9][A-Za-z0-9._-]*$` plus `1..=32` chars. ASCII only.
pub fn is_valid_agent_name(s: &str) -> bool {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    let mut len = 1usize;
    for c in chars {
        len += 1;
        if len > CLAIM_NAME_MAX {
            return false;
        }
        if !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
            return false;
        }
    }
    true
}

/// Validate `ttl_s` for `token_issue`: missing/null → no expiry;
/// number `0` (incl. `-0.0`) → no expiry (legacy falsy `if ttl`);
/// finite `> 0` → `Some(ttl)`; anything else (non-number, bool, string,
/// negative, non-finite) → `Err`. Callers compute `exp = now + ttl` and
/// must check `exp` finite.
pub fn parse_ttl_s(v: Option<&Value>) -> Result<Option<f64>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            let t = n.as_f64().ok_or_else(|| "bad ttl_s: not a number".to_string())?;
            if t == 0.0 {
                return Ok(None);
            }
            if !t.is_finite() {
                return Err("bad ttl_s: must be finite".to_string());
            }
            if t <= 0.0 {
                return Err("bad ttl_s: must be > 0".to_string());
            }
            Ok(Some(t))
        }
        Some(_) => Err("bad ttl_s: must be a number".to_string()),
    }
}

/// Fixed least-privilege grants for issue defaults and all claims.
pub fn default_grants(agent: &str) -> BTreeMap<String, Value> {
    let mut m = BTreeMap::new();
    m.insert("agent".to_string(), json!(agent));
    m.insert("publish".to_string(), json!(["board.*", "inbox.*"]));
    m.insert(
        "subscribe".to_string(),
        json!(["board.*", format!("inbox.{agent}")]),
    );
    m.insert("kv_read".to_string(), json!(["bus.*", "ctx.*"]));
    m.insert("kv_write".to_string(), json!(["bus.*", "ctx.*"]));
    m
}

/// Build an issue entry object (unvalidated `Value`): defaults plus
/// request overrides. `fr` is the wire request object. Rejects a `claim`
/// member (legacy silently dropped it; native refuses explicitly).
/// Callers validate the result via `Policy::from_json` / `from_root`.
pub fn build_issue_entry(agent: &str, exp: Option<f64>, fr: &Value) -> Result<Value, String> {
    let obj = fr.as_object().ok_or_else(|| "bad request".to_string())?;
    if obj.contains_key("claim") {
        return Err("claim not allowed in issue".to_string());
    }
    let mut out = default_grants(agent);
    for key in ["publish", "subscribe", "kv_read", "kv_write"] {
        if let Some(v) = obj.get(key) {
            out.insert(key.to_string(), v.clone());
        }
    }
    for key in ["art_quota_bytes", "rate_per_s", "topic_rates"] {
        match obj.get(key) {
            None | Some(Value::Null) => {}
            Some(v) => {
                out.insert(key.to_string(), v.clone());
            }
        }
    }
    if let Some(e) = exp {
        out.insert("exp".to_string(), json!(e));
    }
    Ok(Value::Object(out.into_iter().collect()))
}

/// Build a fixed claim entry object (unvalidated `Value`, no overrides).
pub fn build_claim_entry(wanted: &str) -> Value {
    Value::Object(default_grants(wanted).into_iter().collect())
}

/// Load the raw token-file root (token objects + preserved meta) for
/// verbatim rewrites. Returns the object map; callers validate via
/// `TokenStore::from_root` after insert/remove. Errors never include
/// token secrets (positional IO/JSON messages only).
pub fn load_raw_root(path: &Path) -> Result<BTreeMap<String, Value>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("token file unreadable: {e}"))?;
    let text = std::str::from_utf8(&raw).map_err(|e| format!("token file not UTF-8: {e}"))?;
    let value: Value =
        serde_json::from_str(text).map_err(|e| format!("token file invalid JSON: {e}"))?;
    match value {
        Value::Object(map) => Ok(map.into_iter().collect()),
        _ => Err("token file root must be an object".to_string()),
    }
}

/// True when `v` is a token entry (JSON object); non-objects are `meta`.
pub fn is_token_entry(v: &Value) -> bool {
    v.is_object()
}

/// Prune a claim history to the rolling window (`now - t < 3600`).
/// Non-finite `now` clears (fail-closed, never mass-allow).
pub fn prune_claim_history(hist: &mut Vec<f64>, now: f64) {
    if !now.is_finite() {
        hist.clear();
        return;
    }
    hist.retain(|t| t.is_finite() && now - *t < CLAIM_WINDOW_S);
}

/// Secure random hex (`nbytes` → `2*nbytes` lowercase hex chars) from
/// `/dev/urandom`. Refuses on any IO/short-read failure (no fallback).
pub fn secure_random_hex(nbytes: usize) -> Result<String, String> {
    use std::io::Read;
    if nbytes == 0 || nbytes > 64 {
        return Err("bad random length".to_string());
    }
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("rng unavailable: {e}"))?;
    let mut buf = vec![0u8; nbytes];
    f.read_exact(&mut buf)
        .map_err(|e| format!("rng unavailable: {e}"))?;
    let mut out = String::with_capacity(nbytes * 2);
    for b in buf {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    Ok(out)
}

/// `tok-{agent}-{hex}` ID. Caller must have validated `agent` and
/// generated `hex` via [`secure_random_hex`].
pub fn make_token(agent: &str, hex: &str) -> String {
    format!("tok-{agent}-{hex}")
}

/// Tmp sibling for atomic replacement (`{path}.tmp`, legacy name).
pub fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Atomically replace `path` with `value` (pretty JSON, `0600`).
/// Sorted-key order (no `topic_rates` order preservation); wire mutations
/// must use [`render_tokens_root_ordered`] + [`persist_tokens_text`] to
/// preserve first-match order. Failpoints as below.
pub fn persist_tokens_file(path: &Path, value: &Value, failpoint: u8) -> Result<(), PersistError> {
    if failpoint == TOKENS_FAIL_TMP_WRITE {
        return Err(PersistError {
            message: "persist failed: tmp write".to_string(),
            post_rename_uncertain: false,
        });
    }
    let text = serde_json::to_string_pretty(value).map_err(|e| PersistError {
        message: format!("persist failed: encode: {e}"),
        post_rename_uncertain: false,
    })?;
    persist_tokens_text(path, &text, failpoint)
}

/// Atomically replace `path` with pre-rendered `text` (`0600`):
/// create/truncate tmp, `0600`, write, fsync file, rename, fsync parent
/// dir. Failpoints simulate failures for tests (see constants).
/// Pre-rename failures leave `path` untouched; dir-fsync failure sets
/// `post_rename_uncertain` (rename may have happened).
pub fn persist_tokens_text(path: &Path, text: &str, failpoint: u8) -> Result<(), PersistError> {
    use std::io::Write;
    if failpoint == TOKENS_FAIL_TMP_WRITE {
        return Err(PersistError {
            message: "persist failed: tmp write".to_string(),
            post_rename_uncertain: false,
        });
    }
    let tmp = tmp_path_for(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|e| PersistError {
        message: format!("persist failed: tmp open: {e}"),
        post_rename_uncertain: false,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(text.as_bytes()).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        PersistError {
            message: format!("persist failed: tmp write: {e}"),
            post_rename_uncertain: false,
        }
    })?;
    if failpoint == TOKENS_FAIL_TMP_FSYNC {
        let _ = std::fs::remove_file(&tmp);
        return Err(PersistError {
            message: "persist failed: tmp fsync".to_string(),
            post_rename_uncertain: false,
        });
    }
    f.sync_all().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        PersistError {
            message: format!("persist failed: tmp fsync: {e}"),
            post_rename_uncertain: false,
        }
    })?;
    drop(f);
    if failpoint == TOKENS_FAIL_RENAME {
        let _ = std::fs::remove_file(&tmp);
        return Err(PersistError {
            message: "persist failed: rename".to_string(),
            post_rename_uncertain: false,
        });
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        PersistError {
            message: format!("persist failed: rename: {e}"),
            post_rename_uncertain: false,
        }
    })?;
    if failpoint == TOKENS_FAIL_DIR_FSYNC {
        return Err(PersistError {
            message: "persist failed: dir fsync".to_string(),
            post_rename_uncertain: true,
        });
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    match std::fs::File::open(parent).and_then(|d| d.sync_all()) {
        Ok(()) => Ok(()),
        Err(e) => Err(PersistError {
            message: format!("persist failed: dir fsync: {e}"),
            post_rename_uncertain: true,
        }),
    }
}

/// Render a token-file root preserving `topic_rates` first-match order.
///
/// `raw` is the verbatim root map (sorted keys); `ordered_rates` maps each
/// token with non-empty rules to its ordered `(pattern, value)` pairs
/// (live file order for existing tokens, validated order for new ones).
/// Root keys and entry fields stay sorted; only `topic_rates` objects for
/// listed tokens emit in the given order (values from `raw` when present,
/// preserving int/float formatting, else the supplied `Value`).
/// Output is 2-space pretty JSON without trailing newline (like
/// `to_string_pretty`), parseable by `TokenStore::from_json_str` with the
/// same first-match order. Errors never include token secrets.
pub fn render_tokens_root_ordered(
    raw: &BTreeMap<String, Value>,
    ordered_rates: &BTreeMap<String, Vec<(String, Value)>>,
) -> Result<String, String> {
    if raw.is_empty() {
        return Ok("{}".to_string());
    }
    let mut out = String::from("{\n");
    let n = raw.len();
    for (i, (key, val)) in raw.iter().enumerate() {
        let key_json = serde_json::to_string(key).map_err(|e| format!("encode failed: {e}"))?;
        out.push_str("  ");
        out.push_str(&key_json);
        out.push_str(": ");
        let rendered = if let Some(obj) = val.as_object() {
            if ordered_rates.contains_key(key) {
                render_token_entry_ordered(key, obj, ordered_rates)
                    .map_err(|e| format!("encode failed: {e}"))?
            } else {
                let pretty =
                    serde_json::to_string_pretty(val).map_err(|e| format!("encode failed: {e}"))?;
                indent_continuation(&pretty, 1)
            }
        } else {
            let pretty =
                serde_json::to_string_pretty(val).map_err(|e| format!("encode failed: {e}"))?;
            indent_continuation(&pretty, 1)
        };
        out.push_str(&rendered);
        if i + 1 < n {
            out.push(',');
        }
        out.push('\n');
    }
    out.push('}');
    Ok(out)
}

fn indent_continuation(pretty: &str, outer_indent: usize) -> String {
    let pad = "  ".repeat(outer_indent);
    let mut lines = pretty.split('\n');
    let first = lines.next().unwrap_or("").to_string();
    let mut out = first;
    for line in lines {
        out.push('\n');
        out.push_str(&pad);
        out.push_str(line);
    }
    out
}

fn render_token_entry_ordered(
    token: &str,
    obj: &serde_json::Map<String, Value>,
    ordered_rates: &BTreeMap<String, Vec<(String, Value)>>,
) -> Result<String, String> {
    let ordered = ordered_rates.get(token).cloned().unwrap_or_default();
    if obj.is_empty() {
        return Ok("{}".to_string());
    }
    let mut out = String::from("{\n");
    let keys: Vec<&String> = obj.keys().collect();
    for (i, field) in keys.iter().enumerate() {
        let field_json =
            serde_json::to_string(field).map_err(|e| format!("encode failed: {e}"))?;
        out.push_str("    ");
        out.push_str(&field_json);
        out.push_str(": ");
        if field.as_str() == "topic_rates" && !ordered.is_empty() {
            out.push_str(&render_ordered_rates(&ordered, obj.get("topic_rates"))?);
        } else {
            let v = obj.get(*field).unwrap_or(&Value::Null);
            let pretty =
                serde_json::to_string_pretty(v).map_err(|e| format!("encode failed: {e}"))?;
            out.push_str(&indent_continuation(&pretty, 2));
        }
        if i + 1 < keys.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  }");
    Ok(out)
}

fn render_ordered_rates(
    ordered: &[(String, Value)],
    raw_rates: Option<&Value>,
) -> Result<String, String> {
    let raw_map = raw_rates.and_then(|v| v.as_object());
    let mut pairs: Vec<(String, Value)> = Vec::with_capacity(ordered.len() + 2);
    for (pat, fallback) in ordered {
        let v = raw_map
            .and_then(|m| m.get(pat))
            .cloned()
            .unwrap_or_else(|| fallback.clone());
        pairs.push((pat.clone(), v));
    }
    if let Some(m) = raw_map {
        for (k, v) in m {
            if !pairs.iter().any(|(p, _)| p == k) {
                pairs.push((k.clone(), v.clone()));
            }
        }
    }
    if pairs.is_empty() {
        return Ok("{}".to_string());
    }
    let mut out = String::from("{\n");
    for (i, (pat, val)) in pairs.iter().enumerate() {
        let pat_json = serde_json::to_string(pat).map_err(|e| format!("encode failed: {e}"))?;
        let val_json = serde_json::to_string(val).map_err(|e| format!("encode failed: {e}"))?;
        out.push_str("      ");
        out.push_str(&pat_json);
        out.push_str(": ");
        out.push_str(&val_json);
        if i + 1 < pairs.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("    }");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_claim_regex_plus_bound() {
        assert!(is_valid_agent_name("a"));
        assert!(is_valid_agent_name("newcomer-alice"));
        assert!(is_valid_agent_name("a.b_c-d/e".replace('/', "").as_str()));
        assert!(!is_valid_agent_name(""));
        assert!(!is_valid_agent_name("*"));
        assert!(!is_valid_agent_name("a*b"));
        assert!(!is_valid_agent_name(".abc"));
        assert!(!is_valid_agent_name("-abc"));
        assert!(!is_valid_agent_name("_abc"));
        assert!(!is_valid_agent_name("a/b"));
        assert!(!is_valid_agent_name("a b"));
        assert!(!is_valid_agent_name(&"a".repeat(33)));
        assert!(is_valid_agent_name(&"a".repeat(32)));
        assert!(!is_valid_agent_name("é"));
    }

    #[test]
    fn ttl_falsy_means_no_expiry_strict_otherwise() {
        assert_eq!(parse_ttl_s(None).unwrap(), None);
        assert_eq!(parse_ttl_s(Some(&json!(null))).unwrap(), None);
        assert_eq!(parse_ttl_s(Some(&json!(0))).unwrap(), None);
        assert_eq!(parse_ttl_s(Some(&json!(0.0))).unwrap(), None);
        assert_eq!(parse_ttl_s(Some(&json!(-0.0))).unwrap(), None);
        assert_eq!(parse_ttl_s(Some(&json!(1))).unwrap(), Some(1.0));
        assert_eq!(parse_ttl_s(Some(&json!(0.5))).unwrap(), Some(0.5));
        assert!(parse_ttl_s(Some(&json!(-1))).is_err());
        assert!(parse_ttl_s(Some(&json!("2"))).is_err());
        assert!(parse_ttl_s(Some(&json!(true))).is_err());
        assert!(parse_ttl_s(Some(&json!([]))).is_err());
        assert!(parse_ttl_s(Some(&json!({}))).is_err());
    }
}

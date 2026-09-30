//! Advisory coordination views: `claims` and `packets` replay reducers.
//!
//! Pure Rust ports of the transitional `busclient.py` advisory helpers
//! (`claim_state`, `short_claims`, `merge_frames_by_ts`, `packet_state`,
//! `short_packets`, `stale_claims`). These views replay finite
//! authenticated history; they are NOT broker atomic lease ownership
//! (`crate::claims`), NOT task completion, and NOT death proofs.
//!
//! Source contracts preserved (traced from current-tree `busclient.py`):
//! - holder-only release, last event wins (`claim_state` 389-417)
//! - structured (`{"event":"claim","packet":...}`) versus string
//!   (`"[claim] packet=..."`) packet conventions, `+`-joined multi packets
//! - leading tags only (`text.lstrip()[:7]`, `key=="claim"/"done"` also
//!   triggers, claim priority over done when both match)
//! - `packet=` keyword search with kv-word lookahead (`by=x` never mints),
//!   single-`#` prefix in text path, `lstrip("#")` cleanup
//! - ready/done/unparsed reporting (first-ready wins, first-done order,
//!   unparsed never silently drops)
//! - stable topic timestamp merge/dedup (`merge_frames_by_ts`: first id
//!   wins, `None` never deduped, stable `ts` sort with missing/non-numeric
//!   as 0, bools as numeric `True=1/False=0`)
//! - stale presence filtering (absent/non-numeric/bool age counts stale)
//! - sorted short output (files/packets/ready/done sorted, unparsed in order)
//!
//! Native notes (explicit, not silent):
//! - No regex crate: packet parsing keeps the legacy ASCII punctuation
//!   and token conventions. Unicode word characters use Rust's
//!   alphanumeric property; this is not exact Python `\w` parity.
//! - `serde_json::Map` is sorted (no `preserve_order`), so multi-key dict
//!   payloads process string values in key-sorted order (legacy used
//!   insertion order). Single-key dicts (common) are unaffected; same-frame
//!   same-packet conflicts resolve by sorted-key order instead of insertion.
//! - JSON `open` objects are key-sorted (legacy preserved first-claim
//!   insertion order). Short output is sorted in both, so no semantic gap.
//! - Non-string holder comparison uses strict JSON equality (legacy Python
//!   `==` would equate `True==1`). Agents are strings in practice.
//! - `task` non-string coercion uses native `value_to_str` (compact JSON
//!   for containers, matching existing CLI divergence from Python `repr`).
//! - Dedup keys use compact JSON text (legacy would crash on unhashable
//!   ids like dicts; native never crashes, dedups by text).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::cmp::Ordering;

use serde_json::Value;

/// Compact JSON text (never fails).
fn compact(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
}

/// Python `str()` for scalar JSON, compact JSON for containers.
/// Matches `src/bin/agent-bus.rs::value_to_str` (documented container
/// divergence from Python `repr`).
fn value_to_str(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => compact(other),
    }
}

/// Compact age like `5s`/`12m`/`2.5h` (`busclient._fmt_age`).
/// Non-numeric input passes through as text; negatives clamp to `0s`.
fn fmt_age_value(v: &Value) -> String {
    let num: Option<f64> = match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    };
    match num {
        None => value_to_str(v),
        Some(mut a) => {
            if !a.is_finite() {
                return value_to_str(v);
            }
            if a < 0.0 {
                a = 0.0;
            }
            if a < 120.0 {
                format!("{a:.0}s")
            } else if a < 7200.0 {
                format!("{:.0}m", a / 60.0)
            } else {
                format!("{:.1}h", a / 3600.0)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// claims
// ---------------------------------------------------------------------------

/// One advisory holding: `{agent, task, ts}` with legacy types preserved
/// (`agent`/`ts` as wire values, `task` coerced to text).
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimHolding {
    pub agent: Value,
    pub task: String,
    pub ts: Value,
}

/// Reduce claim/release posts into current holdings.
///
/// `frames` are delivery frames (`{"msg": {...}}`) in history order; later
/// posts win; a release frees only its holder's files. Payload must be a
/// dict with `event` in `claim`/`release` and `files` a list; each file
/// must be a non-empty string (whitespace-only accepted, like legacy).
pub fn claim_state(frames: &[Value]) -> BTreeMap<String, ClaimHolding> {
    let mut held: BTreeMap<String, ClaimHolding> = BTreeMap::new();
    for fr in frames {
        let msg = fr.get("msg").and_then(|m| m.as_object());
        let Some(msg) = msg else { continue };
        let payload = msg.get("payload");
        let Some(obj) = payload.and_then(|p| p.as_object()) else { continue };
        let event = obj.get("event").and_then(|e| e.as_str());
        if event != Some("claim") && event != Some("release") {
            continue;
        }
        let files = obj.get("files").and_then(|f| f.as_array());
        let Some(files) = files else { continue };
        let agent = msg.get("sender").cloned().unwrap_or(Value::String("?".to_string()));
        let task = match obj.get("task") {
            None => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(v) => value_to_str(v),
        };
        let ts = msg.get("ts").cloned().unwrap_or(Value::Null);
        let is_claim = event == Some("claim");
        for f in files {
            let Some(name) = f.as_str() else { continue };
            if name.is_empty() {
                continue;
            }
            if is_claim {
                held.insert(
                    name.to_string(),
                    ClaimHolding { agent: agent.clone(), task: task.clone(), ts: ts.clone() },
                );
            } else if let Some(cur) = held.get(name) {
                if cur.agent == agent {
                    held.remove(name);
                }
            }
        }
    }
    held
}

/// One `file -> agent (task) age` line per holding, sorted by file.
/// `now` injects the clock (CLI passes wall time, tests pin it).
/// Numeric non-bool `ts` renders age, else `?` (legacy rule).
pub fn short_claims(held: &BTreeMap<String, ClaimHolding>, now: f64) -> String {
    let mut lines = Vec::new();
    for (f, info) in held {
        let age = match &info.ts {
            Value::Number(n) => n.as_f64().map(|ts| fmt_age_value(&Value::from(now - ts))).unwrap_or_else(|| "?".to_string()),
            _ => "?".to_string(),
        };
        lines.push(format!("{f} -> {} ({}) {age}", value_to_str(&info.agent), info.task));
    }
    lines.join("\n")
}

/// Subset of `held` whose holder is absent from the `agents` presence
/// response or older than `max_age_s` seconds. Non-dict presence,
/// missing/non-numeric/bool age counts stale (fail visible). Non-dict
/// holdings are dropped (legacy `continue`).
pub fn stale_claims(
    held: &BTreeMap<String, ClaimHolding>,
    agents_resp: &Value,
    max_age_s: f64,
) -> BTreeMap<String, ClaimHolding> {
    let mut out = BTreeMap::new();
    if held.is_empty() {
        return out;
    }
    let agents = agents_resp
        .get("agents")
        .and_then(|a| a.as_object());
    for (f, info) in held {
        let holder_age: Option<f64> = match (&info.agent, agents) {
            (Value::String(name), Some(map)) => map
                .get(name)
                .and_then(|h| h.as_object())
                .and_then(|h| h.get("age_s"))
                .and_then(|a| match a {
                    Value::Number(n) => n.as_f64(),
                    _ => None,
                }),
            _ => None,
        };
        match holder_age {
            Some(age) if age.is_finite() && age <= max_age_s => {}
            _ => {
                out.insert(f.clone(), info.clone());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// merge
// ---------------------------------------------------------------------------

/// Frame `ts` for stable merge sort: numbers as f64, bools as
/// `True=1/False=0` (legacy `isinstance` includes bools), everything else
/// (missing/non-numeric) as 0, sorting first.
fn merge_ts(fr: &Value) -> f64 {
    let ts = fr.get("msg").and_then(|m| m.get("ts"));
    match ts {
        Some(Value::Bool(true)) => 1.0,
        Some(Value::Bool(false)) => 0.0,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Merge per-topic frame lists into one `ts`-ordered list (stable).
/// Duplicates by `msg.id` collapse (first wins; missing/`null` ids are
/// never deduped). Used for multi-topic `packets` so later posts win
/// across topics by server time.
pub fn merge_frames_by_ts(frame_lists: Vec<Vec<Value>>) -> Vec<Value> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut merged: Vec<Value> = Vec::new();
    for frames in frame_lists {
        for fr in frames {
            let mid = fr.get("msg").and_then(|m| m.get("id"));
            match mid {
                None | Some(Value::Null) => merged.push(fr),
                Some(v) => {
                    let key = compact(v);
                    if seen.contains(&key) {
                        continue;
                    }
                    seen.insert(key);
                    merged.push(fr);
                }
            }
        }
    }
    merged.sort_by(|a, b| {
        merge_ts(a).partial_cmp(&merge_ts(b)).unwrap_or(Ordering::Equal)
    });
    merged
}

// ---------------------------------------------------------------------------
// packets
// ---------------------------------------------------------------------------

/// One open packet claim.
#[derive(Clone, Debug, PartialEq)]
pub struct PacketOpen {
    pub agent: Value,
    pub seq: Value,
    pub topic: Option<String>,
}

/// One unparsed claim/done line (named no packet, never silently dropped).
#[derive(Clone, Debug, PartialEq)]
pub struct PacketUnparsed {
    pub seq: Value,
    pub op: String,
    pub agent: Value,
    pub topic: Option<String>,
}

/// Packet holdings: open claims, ready-unclaimed (first-ready order),
/// done-in-window (first-done order), unparsed (frame order).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PacketState {
    pub open: BTreeMap<String, PacketOpen>,
    pub ready: Vec<String>,
    pub done: Vec<String>,
    pub unparsed: Vec<PacketUnparsed>,
}

fn is_word_dot_hyphen(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '.' || c == '-'
}

/// Negative-lookahead check for the legacy packet token rule:
/// after a candidate token, the remainder must NOT match
/// `[\w\-.]*\s*=` (a kv word like `by=x`, or partial-word backtracking).
/// Returns true when the lookahead MATCHES (token rejected).
fn packet_lookahead_blocks(rest: &str) -> bool {
    let mut it = rest.chars().peekable();
    while let Some(&c) = it.peek() {
        if is_word_dot_hyphen(c) {
            it.next();
        } else {
            break;
        }
    }
    while let Some(&c) = it.peek() {
        if c.is_whitespace() {
            it.next();
        } else {
            break;
        }
    }
    matches!(it.peek(), Some('='))
}

/// Parse one packet token at `s` (optional single `#`, then `[\w\-.]+`
/// with kv lookahead). Returns
/// `(clean_name, bytes_consumed)` on success, where `clean_name` has the
/// single leading `#` stripped (legacy `lstrip("#")` on single-`#` input).
fn parse_packet_token(s: &str) -> Option<(String, usize)> {
    let mut pos = 0usize;
    if s[pos..].starts_with('#') {
        pos += 1;
    }
    let word_start = pos;
    let mut word_end = pos;
    for (i, c) in s[pos..].char_indices() {
        if is_word_dot_hyphen(c) {
            word_end = pos + i + c.len_utf8();
        } else {
            break;
        }
    }
    if word_end == word_start {
        return None;
    }
    // If the full word's suffix matches the blocking lookahead, every
    // shorter prefix also blocks: its remaining word characters are
    // consumed by the same `[word]*` prefix before that suffix. There is
    // no successful shorter token to discover by rescanning each prefix.
    if packet_lookahead_blocks(&s[word_end..]) {
        None
    } else {
        Some((s[word_start..word_end].to_string(), word_end))
    }
}

fn skip_ws(s: &str, mut pos: usize) -> usize {
    while pos < s.len() {
        let Some(c) = s[pos..].chars().next() else { break };
        if c.is_whitespace() {
            pos += c.len_utf8();
        } else {
            break;
        }
    }
    pos
}

/// Legacy `packet\s*[=: ]\s*(...)` search (case-sensitive, first match
/// wins). Returns cleaned packet names (`+`-split, stripped, `#`-stripped).
fn find_packet_clause(text: &str) -> Option<Vec<String>> {
    let mut search_from = 0usize;
    while search_from + 6 <= text.len() {
        let Some(rel) = text[search_from..].find("packet") else { break };
        let after_keyword = search_from + rel + 6;
        let ws_end = skip_ws(text, after_keyword);
        // Legacy `packet\s*[=: ]\s*` backtracks: a space separator may hide
        // inside the leading `\s*` (e.g. `packet E1`). Accept `=`/`:` next,
        // else accept when the skipped whitespace contained a space.
        let mut pos = match text[ws_end..].chars().next() {
            Some('=') | Some(':') => skip_ws(text, ws_end + 1),
            _ if text[after_keyword..ws_end].contains(' ') => ws_end,
            _ => {
                search_from = search_from + rel + 1;
                continue;
            }
        };
        // `ws_end` already skipped all whitespace, but keep the second
        // `\s*` step explicit for `=`/`:` paths (no-op otherwise).
        pos = skip_ws(text, pos);
        let rest = &text[pos..];
        let Some((first, used)) = parse_packet_token(rest) else {
            search_from = search_from + rel + 1;
            continue;
        };
        let mut names = vec![first];
        let mut cur = pos + used;
        loop {
            let k = skip_ws(text, cur);
            if text[k..].starts_with('+') {
                let mut np = k + 1;
                np = skip_ws(text, np);
                match parse_packet_token(&text[np..]) {
                    Some((name, used2)) => {
                        names.push(name);
                        cur = np + used2;
                    }
                    None => break,
                }
            } else {
                break;
            }
        }
        return Some(names);
    }
    None
}

/// Legacy `re.sub(r"\[packet-ready\]\s*packet\s*[=: ]\s*", "[packet-ready] ",
/// text, count=1)`: strip the `packet=` keyword after the first matching
/// `[packet-ready]` tag (first tag whose suffix matches wins).
fn strip_packet_ready_keyword(text: &str) -> String {
    let tag = "[packet-ready]";
    let mut search_from = 0usize;
    while search_from + tag.len() <= text.len() {
        let Some(rel) = text[search_from..].find(tag) else { break };
        let abs_tag = search_from + rel;
        let mut pos = abs_tag + tag.len();
        pos = skip_ws(text, pos);
        if text[pos..].starts_with("packet") {
            let after_keyword = pos + 6;
            let ws_end = skip_ws(text, after_keyword);
            let q = match text[ws_end..].chars().next() {
                Some('=') | Some(':') => skip_ws(text, ws_end + 1),
                _ if text[after_keyword..ws_end].contains(' ') => ws_end,
                _ => {
                    search_from = abs_tag + 1;
                    continue;
                }
            };
            let mut out = String::with_capacity(text.len());
            out.push_str(&text[..abs_tag]);
            out.push_str("[packet-ready] ");
            out.push_str(&text[q..]);
            return out;
        }
        search_from = abs_tag + 1;
    }
    text.to_string()
}

/// Legacy `re.match(r"\s*\[packet-ready\]\s*#?([\w\-.]+)", ready_text)`:
/// leading tag only (after optional whitespace), single packet, first wins
/// at the call site. No kv lookahead (legacy parity).
fn parse_ready_packet(ready_text: &str) -> Option<String> {
    let mut pos = skip_ws(ready_text, 0);
    if !ready_text[pos..].starts_with("[packet-ready]") {
        return None;
    }
    pos += "[packet-ready]".len();
    pos = skip_ws(ready_text, pos);
    if ready_text[pos..].starts_with('#') {
        pos += 1;
    }
    let start = pos;
    let mut end = pos;
    for (i, c) in ready_text[pos..].char_indices() {
        if is_word_dot_hyphen(c) {
            end = pos + i + c.len_utf8();
        } else {
            break;
        }
    }
    if end == start {
        return None;
    }
    Some(ready_text[start..end].to_string())
}

/// Reduce announce posts into packet holdings.
///
/// Accepts string bodies (`"[claim] packet=P50"`) and dict bodies
/// (`{"claim": "packet 44-46"}`). One `packet=` keyword may name several
/// packets joined by `+`. Later posts win; a done frees its packet(s).
/// Claim/done lines naming no packet become `unparsed` (never dropped).
/// With `with_topics`, open and unparsed entries carry their `msg.topic`.
pub fn packet_state(frames: &[Value], with_topics: bool) -> PacketState {
    let mut open: BTreeMap<String, PacketOpen> = BTreeMap::new();
    let mut ready_map: HashMap<String, (Value, Value)> = HashMap::new();
    let mut ready_order: Vec<String> = Vec::new();
    let mut done: Vec<String> = Vec::new();
    let mut unparsed: Vec<PacketUnparsed> = Vec::new();

    for fr in frames {
        let msg_obj = fr.get("msg").and_then(|m| m.as_object());
        let msg_null = serde_json::Map::new();
        let msg = msg_obj.unwrap_or(&msg_null);
        let payload = msg.get("payload");
        let sender = msg.get("sender").cloned().unwrap_or(Value::String("?".to_string()));
        let seq = msg.get("seq").cloned().unwrap_or(Value::String("?".to_string()));
        let topic = if with_topics {
            msg.get("topic").and_then(|t| t.as_str()).map(|s| s.to_string())
        } else {
            None
        };

        let mut texts: Vec<(Option<String>, String)> = Vec::new();
        let mut agent = sender.clone();
        let mut handled_structured = false;
        match payload {
            Some(Value::String(s)) => texts.push((None, s.clone())),
            Some(Value::Object(obj)) => {
                if let Some(from) = obj.get("from") {
                    agent = from.clone();
                }
                let event = obj.get("event").and_then(|e| e.as_str());
                let structured = (event == Some("claim") || event == Some("done"))
                    && matches!(obj.get("packet"), Some(Value::String(p)) if !p.is_empty());
                if structured {
                    let packet = obj.get("packet").and_then(|p| p.as_str()).unwrap_or("");
                    let name = packet.trim_start_matches('#').to_string();
                    if event == Some("claim") {
                        open.insert(
                            name,
                            PacketOpen { agent: agent.clone(), seq: seq.clone(), topic: topic.clone() },
                        );
                    } else {
                        open.remove(&name);
                        if !done.contains(&name) {
                            done.push(name);
                        }
                    }
                    handled_structured = true;
                }
                if !handled_structured {
                    // `serde_json::Map` iterates key-sorted (no
                    // `preserve_order`); single-key dicts unaffected.
                    for (k, v) in obj {
                        if let Value::String(s) = v {
                            texts.push((Some(k.clone()), s.clone()));
                        }
                    }
                }
            }
            _ => continue,
        }
        if handled_structured {
            continue;
        }

        for (key, text) in &texts {
            let head: String = text.trim_start().chars().take(7).collect();
            let mut op: Option<&str> = None;
            if head.starts_with("[claim]") || key.as_deref() == Some("claim") {
                op = Some("claim");
            } else if head.starts_with("[done]") || key.as_deref() == Some("done") {
                op = Some("done");
            }
            if let Some(op) = op {
                if let Some(packets) = find_packet_clause(text) {
                    for name in packets {
                        if op == "claim" {
                            open.insert(
                                name,
                                PacketOpen { agent: agent.clone(), seq: seq.clone(), topic: topic.clone() },
                            );
                        } else {
                            open.remove(&name);
                            if !done.contains(&name) {
                                done.push(name);
                            }
                        }
                    }
                } else {
                    unparsed.push(PacketUnparsed {
                        seq: seq.clone(),
                        op: op.to_string(),
                        agent: agent.clone(),
                        topic: topic.clone(),
                    });
                }
            }
            let ready_text = strip_packet_ready_keyword(text);
            if let Some(name) = parse_ready_packet(&ready_text) {
                if !ready_map.contains_key(&name) {
                    ready_map.insert(name.clone(), (agent.clone(), seq.clone()));
                    ready_order.push(name);
                }
            }
        }
    }

    let mut ready: Vec<String> = Vec::new();
    for name in ready_order {
        if !open.contains_key(&name) && !done.contains(&name) {
            ready.push(name);
        }
    }
    PacketState { open, ready, done, unparsed }
}

/// One `packet <- agent (seq N[@topic])` line per open claim (sorted),
/// then `ready unclaimed:` / `done in window:` summaries (sorted), then
/// `unparsed claim/done: seq ...` in frame order. Empty open renders
/// `(no open packet claims)` (legacy parity).
pub fn short_packets(state: &PacketState) -> String {
    let mut lines: Vec<String> = Vec::new();
    for (packet, info) in &state.open {
        let mut wh = format!("seq {}", value_to_str(&info.seq));
        if let Some(t) = &info.topic {
            if !t.is_empty() {
                wh.push('@');
                wh.push_str(t);
            }
        }
        lines.push(format!("{packet} <- {} ({wh})", value_to_str(&info.agent)));
    }
    if lines.is_empty() {
        lines.push("(no open packet claims)".to_string());
    }
    if !state.ready.is_empty() {
        let mut r = state.ready.clone();
        r.sort();
        lines.push(format!("ready unclaimed: {}", r.join(", ")));
    }
    if !state.done.is_empty() {
        let mut d = state.done.clone();
        d.sort();
        lines.push(format!("done in window: {}", d.join(", ")));
    }
    if !state.unparsed.is_empty() {
        let mut refs = Vec::new();
        for u in &state.unparsed {
            let mut r = value_to_str(&u.seq);
            if let Some(t) = &u.topic {
                if !t.is_empty() {
                    r.push('@');
                    r.push_str(t);
                }
            }
            refs.push(r);
        }
        lines.push(format!("unparsed claim/done: seq {}", refs.join(", ")));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frame(sender: &str, seq: u64, ts: Value, payload: Value) -> Value {
        json!({"msg": {"sender": sender, "seq": seq, "ts": ts, "id": format!("id{seq}"), "payload": payload}})
    }

    #[test]
    fn claims_holder_only_release_last_wins() {
        let frames = vec![
            frame("alice", 1, json!(100.0), json!({"event": "claim", "task": "t1", "files": ["f.rs"]})),
            frame("bob", 2, json!(101.0), json!({"event": "claim", "task": "t2", "files": ["f.rs"]})),
            frame("alice", 3, json!(102.0), json!({"event": "release", "task": "t1", "files": ["f.rs"]})),
        ];
        let held = claim_state(&frames);
        assert_eq!(held.len(), 1);
        assert_eq!(held["f.rs"].agent, json!("bob"));
        let frames2 = vec![
            frame("alice", 1, json!(100.0), json!({"event": "claim", "task": "t1", "files": ["a.rs", "b.rs"]})),
            frame("alice", 2, json!(101.0), json!({"event": "release", "task": "t1", "files": ["a.rs"]})),
        ];
        let held2 = claim_state(&frames2);
        assert_eq!(held2.len(), 1);
        assert!(held2.contains_key("b.rs"));
    }

    #[test]
    fn merge_dedups_stable_by_ts_bool_numeric() {
        let mut a = frame("a", 1, json!(true), json!("x"));
        a["msg"]["id"] = json!("dup");
        let mut b = frame("b", 2, json!(1.0), json!("y"));
        b["msg"]["id"] = json!("dup");
        let mut c = frame("c", 3, json!(0.0), json!("z"));
        c["msg"]["id"] = json!("c3");
        let merged = merge_frames_by_ts(vec![vec![a.clone(), c.clone()], vec![b.clone()]]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0]["msg"]["id"], json!("c3"));
        assert_eq!(merged[1]["msg"]["sender"], json!("a"));
    }

    #[test]
    fn packets_leading_tags_plus_split_and_unparsed() {
        let frames = vec![
            frame("a", 1, json!(1.0), json!("[claim] packet=RUST-B + RUST-D")),
            frame("b", 2, json!(2.0), json!("how to [claim] packet=RUST-X here")),
            frame("c", 3, json!(3.0), json!("[claim] RUST-D P2")),
        ];
        let st = packet_state(&frames, false);
        assert!(st.open.contains_key("RUST-B"));
        assert!(st.open.contains_key("RUST-D"));
        assert!(!st.open.contains_key("RUST-X"));
        assert_eq!(st.unparsed.len(), 1);
        assert_eq!(st.unparsed[0].seq, json!(3));
    }
}

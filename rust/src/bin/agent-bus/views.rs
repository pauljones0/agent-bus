//! Advisory `claims` and `packets` views over finite validated history.
//!
//! Native replacements for the legacy subscription-drain views (`bus`
//! `claims`/`packets`, `busclient.py` reducers). Historical messages are
//! finite; completeness/cursors/gaps are explicit. `claims` replay is NOT
//! broker atomic lease ownership (`agent_bus::claims`); `packets --tail`
//! is intentionally a window; cross-topic snapshots are NOT globally
//! atomic. Incomplete history/window/retention/gap/missing presence never
//! proves a resource free, an agent dead, or a task complete.

use agent_bus::advisory;
use serde_json::{json, Value};

const CLAIMS_USAGE: &str = "usage: agent-bus claims [TOPIC] [--format short|json] [--stale AGE] [--timeout S]\n\
 \n\
 Advisory holdings on TOPIC (default board.build) from finite validated\n\
 history (fetch with pinned snapshot, never wall-clock drains). Later\n\
 posts win; a release frees only its holder's files. This is NOT broker\n\
 atomic lease ownership; absence proves nothing when history is\n\
 incomplete. --stale AGE keeps only holdings whose holder is absent or\n\
 older than AGE (heartbeat presence, not task state; missing counts\n\
 stale). --timeout S (default 5) bounds fetch network time; a timeout\n\
 fails closed, never partial success.\n";

const PACKETS_USAGE: &str = "usage: agent-bus packets [TOPIC ...] [--tail N] [--format short|json]\n\
 \n\
 Advisory packet holdings from the last N sequence positions per topic (default\n\
 board.announce, N=60). String (`[claim] packet=P50`) and structured\n\
 (`{\"event\":\"claim\",\"packet\":...}`) conventions; leading tags only;\n\
 `+` joins multi packets; ready/done/unparsed reported; multi-topic\n\
 merges dedup by id and sort stably by server ts (later wins across\n\
 topics). --tail is intentionally a window; cross-topic snapshots are\n\
 NOT globally atomic. Gaps within the window warn and exit 2.\n";

struct FetchMeta {
    snapshot_seq: u64,
    topic_seq: u64,
    had_gap: bool,
    missing: u64,
    missing_ranges: Vec<Value>,
}

fn fetch_topic_history(
    client: &mut agent_bus::wire::Client,
    topic: &str,
    deadline: std::time::Instant,
) -> Result<(Vec<Value>, FetchMeta), String> {
    let mut cursor: u64 = 0;
    let mut snapshot: Option<u64> = None;
    let mut messages: Vec<Value> = Vec::new();
    let mut had_gap = false;
    let mut missing_total: u64 = 0;
    let mut ranges: Vec<Value> = Vec::new();
    let mut topic_seq: u64 = 0;
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| format!("fetch on '{topic}' timed out; resume with --since-seq {cursor}"))?;
        client
            .set_rpc_timeout(remaining.min(agent_bus::wire::CLIENT_RPC_TIMEOUT))
            .map_err(|e| e.to_string())?;
        let mut req = json!({"op": "fetch", "topic": topic, "from_seq": cursor, "limit": 500});
        if let Some(s) = snapshot {
            req["until_seq"] = json!(s);
        }
        let resp = match client.rpc(&req) {
            Ok(r) => r,
            Err(e) => {
                return Err(format!(
                    "history catch-up incomplete on '{topic}': {e}; resume with --since-seq {cursor}"
                ));
            }
        };
        if let Some(err) = resp.get("error") {
            return Err(format!(
                "history catch-up incomplete on '{topic}': {}; resume with --since-seq {cursor}",
                super::err_text(err)
            ));
        }
        let page = match super::validate_history(&resp, topic, cursor, snapshot) {
            Ok(p) => p,
            Err(e) => {
                return Err(format!(
                    "history catch-up incomplete on '{topic}': {e}; resume with --since-seq {cursor}"
                ));
            }
        };
        snapshot = Some(page.snapshot_seq);
        // `topic_seq` is not in `HistoryPage`; re-read from the validated
        // cursor (already checked by `validate_history`).
        topic_seq = resp
            .get("cursor")
            .and_then(|c| c.get("topic_seq"))
            .and_then(|v| v.as_u64())
            .unwrap_or(topic_seq);
        for m in &page.messages {
            messages.push(m.clone());
        }
        cursor = page.next_seq;
        if page.gap {
            had_gap = true;
            missing_total = missing_total.saturating_add(page.missing);
            if let Some(arr) = page.missing_ranges.as_array() {
                for r in arr {
                    ranges.push(r.clone());
                }
            }
        }
        if !page.has_more {
            let snap = snapshot.unwrap_or(0);
            return Ok((
                messages,
                FetchMeta {
                    snapshot_seq: snap,
                    topic_seq,
                    had_gap,
                    missing: missing_total,
                    missing_ranges: ranges,
                },
            ));
        }
    }
}

pub(super) fn command_claims(argv: &[String]) -> i32 {
    if super::wants_help(argv) {
        print!("{CLAIMS_USAGE}");
        return 0;
    }
    let mut topic: Option<String> = None;
    let mut format = "short".to_string();
    let mut stale: Option<String> = None;
    let mut timeout: f64 = 5.0;
    let mut literal = false;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && a == "--format" {
            match super::take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--stale" {
            match super::take_value(argv, &mut i, "--stale") {
                Ok(v) => stale = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--timeout" {
            match super::take_value(argv, &mut i, "--timeout") {
                Ok(v) => match v.parse::<f64>() {
                    Ok(n) if n.is_finite() && n > 0.0 => timeout = n,
                    _ => {
                        eprintln!("error: bad --timeout {v}: want positive seconds");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && super::is_flag(a) {
            eprintln!("error: unknown claims option '{a}'\n{CLAIMS_USAGE}");
            return 2;
        }
        if topic.is_some() {
            eprintln!("error: claims takes a single topic\n{CLAIMS_USAGE}");
            return 2;
        }
        topic = Some(a.to_string());
        i += 1;
    }
    let topic = topic.unwrap_or_else(|| "board.build".to_string());
    if topic.chars().any(|c| c == '*' || c == '?' || c == '[') {
        eprintln!("error: claims needs a single topic, not a pattern");
        return 2;
    }
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let max_age = match stale.as_deref() {
        None => None,
        Some(s) => match super::parse_age(s) {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("error: bad --stale value: {e}");
                return 1;
            }
        },
    };
    let timeout_dur = match std::time::Duration::try_from_secs_f64(timeout) {
        Ok(d) if !d.is_zero() && std::time::Instant::now().checked_add(d).is_some() => d,
        _ => {
            eprintln!("error: --timeout is outside the supported clock range");
            return 2;
        }
    };
    let cfg = match super::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match super::connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let Some(deadline) = std::time::Instant::now().checked_add(timeout_dur) else {
        eprintln!("error: --timeout is outside the supported clock range");
        return 2;
    };
    let (messages, meta) = match fetch_topic_history(&mut client, &topic, deadline) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let frames: Vec<Value> = messages.iter().map(|m| json!({"msg": m})).collect();
    let held_full = advisory::claim_state(&frames);
    let held = match max_age {
        None => held_full.clone(),
        Some(max) => {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .filter(|d| !d.is_zero());
            let Some(rem) = remaining else {
                eprintln!("error: presence fetch timed out; no stale view");
                return 1;
            };
            if let Err(e) = client.set_rpc_timeout(rem.min(agent_bus::wire::CLIENT_RPC_TIMEOUT)) {
                eprintln!("error: {e}");
                return 1;
            }
            match super::rpc(&mut client, &json!({"op": "agents"})) {
                Ok(resp) => advisory::stale_claims(&held_full, &resp, max),
                Err(e) => {
                    eprintln!("error: presence fetch failed: {e}; no stale view");
                    return 1;
                }
            }
        }
    };
    let now = super::now_secs();
    if format == "json" {
        let mut held_json = serde_json::Map::new();
        for (f, h) in &held {
            held_json.insert(
                f.clone(),
                json!({"agent": h.agent, "task": h.task, "ts": h.ts}),
            );
        }
        let view = json!({
            "view": "claims",
            "topic": topic,
            "source": "history_replay",
            "advisory": true,
            "atomic_lease": false,
            "held": held_json,
            "stale_filter": max_age.map(|m| json!({"max_age_s": m, "missing_means": "stale-or-unknown"})),
            "completeness": {
                "from_seq": 0,
                "through_seq": meta.snapshot_seq,
                "snapshot_seq": meta.snapshot_seq,
                "topic_seq": meta.topic_seq,
                "had_gap": meta.had_gap,
                "missing": meta.missing,
                "missing_ranges": meta.missing_ranges,
                "complete": !meta.had_gap,
                "fetch_timeout_s": timeout,
            },
            "note": "advisory replay only, not broker atomic lease ownership; absence proves nothing when incomplete; stale uses heartbeat presence, not task state",
        });
        println!("{}", super::compact(&view));
        if meta.had_gap {
            eprintln!(
                "warning: retention gap or expired history on '{topic}': {} unavailable message(s), ranges {}; showing survivors",
                meta.missing,
                super::compact(&Value::Array(meta.missing_ranges))
            );
            return 2;
        }
        return 0;
    }
    // short
    let text = advisory::short_claims(&held, now);
    if !text.is_empty() {
        println!("{text}");
        if meta.had_gap {
            eprintln!(
                "warning: retention gap or expired history on '{topic}': {} unavailable message(s), ranges {}; showing survivors",
                meta.missing,
                super::compact(&Value::Array(meta.missing_ranges))
            );
            return 2;
        }
        return 0;
    }
    if meta.had_gap {
        eprintln!(
            "warning: retention gap or expired history on '{topic}': {} unavailable message(s), ranges {}; no survivors to show, absence unproven",
            meta.missing,
            super::compact(&Value::Array(meta.missing_ranges))
        );
        return 2;
    }
    if max_age.is_some() && !held_full.is_empty() {
        eprintln!(
            "note: no stale claims on '{topic}' ({} held, filter {})",
            held_full.len(),
            stale.unwrap_or_default()
        );
    } else {
        eprintln!("note: no claims held on '{topic}'");
    }
    0
}

pub(super) fn command_packets(argv: &[String]) -> i32 {
    if super::wants_help(argv) {
        print!("{PACKETS_USAGE}");
        return 0;
    }
    let mut topics: Vec<String> = Vec::new();
    let mut tail: i64 = 60;
    let mut format = "short".to_string();
    let mut literal = false;
    let mut i = 2;
    while i < argv.len() {
        let a = argv[i].as_str();
        if !literal && a == "--" {
            literal = true;
            i += 1;
            continue;
        }
        if !literal && a == "--tail" {
            match super::take_value(argv, &mut i, "--tail") {
                Ok(v) => match v.parse::<i64>() {
                    Ok(n) => tail = n,
                    Err(_) => {
                        eprintln!("error: bad --tail {v}: want >= 1");
                        return 2;
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && a == "--format" {
            match super::take_value(argv, &mut i, "--format") {
                Ok(v) => format = v,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            }
            i += 1;
            continue;
        }
        if !literal && super::is_flag(a) {
            eprintln!("error: unknown packets option '{a}'\n{PACKETS_USAGE}");
            return 2;
        }
        topics.push(a.to_string());
        i += 1;
    }
    if topics.is_empty() {
        topics.push("board.announce".to_string());
    }
    for t in &topics {
        if t.chars().any(|c| c == '*' || c == '?' || c == '[') {
            eprintln!("error: packets needs exact topics, not patterns");
            return 2;
        }
    }
    if tail < 1 {
        eprintln!("error: bad --tail {tail}: want >= 1");
        return 2;
    }
    if !["json", "short"].contains(&format.as_str()) {
        eprintln!("error: bad --format {format}: want json|short");
        return 2;
    }
    let tail_u = tail as u64;
    let cfg = match super::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut client = match super::connect(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let with_topics = topics.len() > 1;
    let mut per_topic_frames: Vec<Vec<Value>> = Vec::new();
    let mut per_topic_meta: Vec<(String, FetchMeta, Vec<Value>, bool)> = Vec::new();
    for topic in &topics {
        let (messages, meta) = match fetch_topic_history(&mut client, topic, deadline) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        };
        let window_start = meta.snapshot_seq.saturating_sub(tail_u);
        let mut window: Vec<Value> = Vec::new();
        for m in &messages {
            if m.get("seq").and_then(|v| v.as_u64()).is_some_and(|s| s > window_start) {
                window.push(m.clone());
            }
        }
        // Gaps within the window (last `tail` seqs) make the window incomplete.
        let mut gap_in_window = false;
        for r in &meta.missing_ranges {
            if let Some(arr) = r.as_array() {
                if arr.len() == 2 {
                    if let (Some(a), Some(b)) = (arr[0].as_u64(), arr[1].as_u64()) {
                        if b > window_start && a <= meta.snapshot_seq {
                            gap_in_window = true;
                            break;
                        }
                    }
                }
            }
        }
        let mut frames: Vec<Value> = Vec::new();
        for mut m in window.clone() {
            if with_topics {
                if let Some(obj) = m.as_object_mut() {
                    obj.insert("topic".to_string(), Value::String(topic.clone()));
                }
            }
            frames.push(json!({"msg": m}));
        }
        per_topic_meta.push((topic.clone(), meta, window, gap_in_window));
        per_topic_frames.push(frames);
    }
    let frames = if per_topic_frames.len() == 1 {
        per_topic_frames.into_iter().next().unwrap_or_default()
    } else {
        advisory::merge_frames_by_ts(per_topic_frames)
    };
    let state = advisory::packet_state(&frames, with_topics);
    let any_gap_in_window = per_topic_meta.iter().any(|(_, _, _, g)| *g);
    if format == "json" {
        let mut open_json = serde_json::Map::new();
        for (p, info) in &state.open {
            let mut e = serde_json::Map::new();
            e.insert("agent".to_string(), info.agent.clone());
            e.insert("seq".to_string(), info.seq.clone());
            if let Some(t) = &info.topic {
                e.insert("topic".to_string(), Value::String(t.clone()));
            }
            open_json.insert(p.clone(), Value::Object(e));
        }
        let mut per_topic_json = Vec::new();
        for (topic, meta, window, gap_w) in &per_topic_meta {
            per_topic_json.push(json!({
                "topic": topic,
                "snapshot_seq": meta.snapshot_seq,
                "topic_seq": meta.topic_seq,
                "window_start": meta.snapshot_seq.saturating_sub(tail_u),
                "window_returned": window.len(),
                "tail": tail_u,
                "gap_in_window": gap_w,
                "had_gap": meta.had_gap,
                "missing": meta.missing,
                "missing_ranges": meta.missing_ranges,
            }));
        }
        let mut view = json!({
            "view": "packets",
            "topics": topics,
            "source": "history_replay",
            "advisory": true,
            "window": {"tail": tail_u, "atomic_snapshot": false, "per_topic": per_topic_json},
            "open": open_json,
            "ready": state.ready,
            "done": state.done,
            "completeness": {
                "gap_in_window": any_gap_in_window,
                "complete_window": !any_gap_in_window,
                "atomic_snapshot": false,
            },
            "note": "tail window only, not full history; cross-topic snapshots are not atomic; absence proves nothing when incomplete",
        });
        if !state.unparsed.is_empty() {
            let mut ups = Vec::new();
            for u in &state.unparsed {
                let mut e = serde_json::Map::new();
                e.insert("seq".to_string(), u.seq.clone());
                e.insert("op".to_string(), Value::String(u.op.clone()));
                e.insert("agent".to_string(), u.agent.clone());
                if let Some(t) = &u.topic {
                    e.insert("topic".to_string(), Value::String(t.clone()));
                }
                ups.push(Value::Object(e));
            }
            view["unparsed"] = Value::Array(ups);
        }
        println!("{}", super::compact(&view));
        if with_topics {
            eprintln!("note: cross-topic snapshots are not atomic; merged by server ts");
        }
        if any_gap_in_window {
            eprintln!("warning: retention gap within the tail window; showing survivors, absence unproven");
            return 2;
        }
        return 0;
    }
    println!("{}", advisory::short_packets(&state));
    if with_topics {
        eprintln!("note: cross-topic snapshots are not atomic; merged by server ts");
    }
    if any_gap_in_window {
        eprintln!("warning: retention gap within the tail window; showing survivors, absence unproven");
        return 2;
    }
    0
}

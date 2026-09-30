//! Advisory `claims`/`packets` views: pure reducers + scripted CLI.
//!
//! Tiny constructive checks only: pure reducer contracts (holder-only
//! release, last wins, leading tags, `+` multi, ready/done/unparsed,
//! stable ts merge/dedup, stale filtering, sorted short) plus owned
//! loopback fixtures returning a few benign ordinary pages (short/json,
//! stale, tail windows, gaps, denied pages, usage). No live broker,
//! floods, races, or failure injection.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use agent_bus::advisory::{
    claim_state, merge_frames_by_ts, packet_state, short_claims, short_packets, stale_claims,
};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// pure reducers
// ---------------------------------------------------------------------------

fn fr(sender: Value, seq: Value, ts: Value, payload: Value) -> Value {
    json!({"msg": {"sender": sender, "seq": seq, "ts": ts, "id": "x", "payload": payload}})
}

fn fr_id(id: &str, sender: &str, seq: u64, ts: Value, payload: Value) -> Value {
    json!({"msg": {"sender": sender, "seq": seq, "ts": ts, "id": id, "payload": payload}})
}

#[test]
fn claims_holder_only_release_last_wins_and_shapes() {
    let frames = vec![
        fr(json!("alice"), json!(1), json!(100.0), json!({"event": "claim", "task": "t1", "files": ["f.rs", "", 7, "g.rs"]})),
        fr(json!("bob"), json!(2), json!(101.0), json!({"event": "claim", "task": 9, "files": ["f.rs"]})),
        fr(json!("alice"), json!(3), json!(102.0), json!({"event": "release", "task": "t1", "files": ["f.rs"]})),
        fr(json!("x"), json!(4), json!(103.0), json!("plain string ignored")),
        fr(json!("x"), json!(5), json!(104.0), json!({"event": "claim", "task": "t", "files": "not-a-list"})),
        fr(json!("x"), json!(6), json!(105.0), json!({"event": "note", "task": "t", "files": ["h.rs"]})),
    ];
    let held = claim_state(&frames);
    assert_eq!(held.len(), 2);
    assert_eq!(held["f.rs"].agent, json!("bob"));
    assert_eq!(held["f.rs"].task, "9");
    assert_eq!(held["f.rs"].ts, json!(101.0));
    assert_eq!(held["g.rs"].agent, json!("alice"));
    // holder-only release: bob still holds f.rs after alice's release.
    let rel = vec![
        fr(json!("bob"), json!(7), json!(106.0), json!({"event": "release", "task": "t2", "files": ["f.rs"]})),
    ];
    let mut all = frames.clone();
    all.extend(rel);
    let held2 = claim_state(&all);
    assert!(!held2.contains_key("f.rs"));
    assert!(held2.contains_key("g.rs"));
}

#[test]
fn short_claims_sorted_age_and_question() {
    let frames = vec![
        fr(json!("b"), json!(1), json!(100.0), json!({"event": "claim", "task": "t", "files": ["z.rs"]})),
        fr(json!("a"), json!(2), json!("oops"), json!({"event": "claim", "task": "", "files": ["a.rs"]})),
        fr(json!("c"), json!(3), json!(true), json!({"event": "claim", "task": "x", "files": ["m.rs"]})),
    ];
    let held = claim_state(&frames);
    let text = short_claims(&held, 160.0);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("a.rs -> a () ?"), "{}", text);
    assert!(lines[1].starts_with("m.rs -> c (x) ?"), "{}", text);
    assert!(lines[2].starts_with("z.rs -> b (t) 60s"), "{}", text);
}

#[test]
fn stale_claims_absent_bool_string_age_counts_stale() {
    let frames = vec![
        fr(json!("fresh"), json!(1), json!(1.0), json!({"event": "claim", "task": "t", "files": ["f1"]})),
        fr(json!("old"), json!(2), json!(1.0), json!({"event": "claim", "task": "t", "files": ["f2"]})),
        fr(json!("gone"), json!(3), json!(1.0), json!({"event": "claim", "task": "t", "files": ["f3"]})),
        fr(json!("weird"), json!(4), json!(1.0), json!({"event": "claim", "task": "t", "files": ["f4"]})),
        fr(json!(7), json!(5), json!(1.0), json!({"event": "claim", "task": "t", "files": ["f5"]})),
    ];
    let held = claim_state(&frames);
    let agents = json!({"agents": {
        "fresh": {"age_s": 5.0, "online": true},
        "old": {"age_s": 5000.0, "online": false},
        "weird": {"age_s": "young", "online": true},
    }});
    let stale = stale_claims(&held, &agents, 60.0);
    assert!(!stale.contains_key("f1"));
    assert!(stale.contains_key("f2"));
    assert!(stale.contains_key("f3"));
    assert!(stale.contains_key("f4"));
    assert!(stale.contains_key("f5"));
    let agents_bool = json!({"agents": {"fresh": {"age_s": true}}});
    let stale2 = stale_claims(&held, &agents_bool, 3600.0);
    assert!(stale2.contains_key("f1"));
}

#[test]
fn merge_dedups_first_wins_stable_bool_ts() {
    let a = fr_id("dup", "a", 1, json!(true), json!("A"));
    let b = fr_id("dup", "b", 2, json!(1.0), json!("B"));
    let c = fr_id("c3", "c", 3, json!(0.0), json!("C"));
    let d = json!({"msg": {"sender": "d", "seq": 4, "payload": json!("D")}});
    let e = json!({"msg": {"sender": "e", "seq": 5, "id": Value::Null, "ts": json!("x"), "payload": json!("E")}});
    let merged = merge_frames_by_ts(vec![vec![a, c], vec![b, d.clone(), e]]);
    assert_eq!(merged.len(), 4);
    // ts order: missing/non-numeric (0) first in stable input order (c, d, e),
    // then True=1 (a wins over b by dedup).
    assert_eq!(merged[0]["msg"]["sender"], json!("c"));
    assert_eq!(merged[1]["msg"]["sender"], json!("d"));
    assert_eq!(merged[2]["msg"]["sender"], json!("e"));
    assert_eq!(merged[3]["msg"]["sender"], json!("a"));
}

#[test]
fn packets_structured_string_plus_leading_tags_kv_guard() {
    let frames = vec![
        fr(json!("a"), json!(1), json!(1.0), json!("[claim] packet=RUST-B + RUST-D")),
        fr(json!("b"), json!(2), json!(2.0), json!("how to [claim] packet=RUST-X here")),
        fr(json!("c"), json!(3), json!(3.0), json!("[claim] packet=P1 + by=x")),
        fr(json!("d"), json!(4), json!(4.0), json!({"event": "claim", "packet": "##S1", "from": "dee"})),
        fr(json!("e"), json!(5), json!(5.0), json!({"claim": "packet E1"})),
        fr(json!("f"), json!(6), json!(6.0), json!({"event": "done", "packet": "RUST-B"})),
    ];
    let st = packet_state(&frames, false);
    assert!(!st.open.contains_key("RUST-B"));
    assert!(st.open.contains_key("RUST-D"));
    assert!(!st.open.contains_key("RUST-X"));
    assert!(st.open.contains_key("P1"));
    assert!(!st.open.contains_key("by"));
    assert_eq!(st.open["S1"].agent, json!("dee"));
    assert!(st.open.contains_key("E1"));
    assert_eq!(st.done, vec!["RUST-B".to_string()]);
    assert!(st.unparsed.is_empty());
}

#[test]
fn packets_ready_done_unparsed_with_topics() {
    let mut f1 = fr(json!("a"), json!(11), json!(1.0), json!("[packet-ready] packet=R1"));
    f1["msg"]["topic"] = json!("board.announce");
    let mut f2 = fr(json!("b"), json!(12), json!(2.0), json!("[claim] RUST-D P2"));
    f2["msg"]["topic"] = json!("board.announce");
    let mut f3 = fr(json!("c"), json!(21), json!(3.0), json!("[claim] packet=R1"));
    f3["msg"]["topic"] = json!("board.other");
    let st = packet_state(&[f1, f2, f3], true);
    assert!(st.ready.is_empty());
    assert_eq!(st.open["R1"].topic.as_deref(), Some("board.other"));
    assert_eq!(st.unparsed.len(), 1);
    assert_eq!(st.unparsed[0].topic.as_deref(), Some("board.announce"));
    let text = short_packets(&st);
    assert!(text.contains("R1 <- c (seq 21@board.other)"), "{text}");
    assert!(text.contains("unparsed claim/done: seq 12@board.announce"), "{text}");
}

#[test]
fn short_packets_sorted_ready_done_empty_line() {
    let frames = vec![
        fr(json!("b"), json!(2), json!(2.0), json!("[claim] packet=Z9")),
        fr(json!("a"), json!(1), json!(1.0), json!("[claim] packet=A1")),
        fr(json!("c"), json!(3), json!(3.0), json!("[packet-ready] R2")),
        fr(json!("d"), json!(4), json!(4.0), json!("[packet-ready] R1")),
        fr(json!("e"), json!(5), json!(5.0), json!("[done] packet=D2")),
        fr(json!("f"), json!(6), json!(6.0), json!("[done] packet=D1")),
    ];
    let st = packet_state(&frames, false);
    let text = short_packets(&st);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "A1 <- a (seq 1)");
    assert_eq!(lines[1], "Z9 <- b (seq 2)");
    assert_eq!(lines[2], "ready unclaimed: R1, R2");
    assert_eq!(lines[3], "done in window: D1, D2");
    let empty = packet_state(&[], false);
    assert_eq!(short_packets(&empty), "(no open packet claims)");
}

// ---------------------------------------------------------------------------
// scripted CLI (owned loopback, few benign pages)
// ---------------------------------------------------------------------------

fn bin() -> String {
    env!("CARGO_BIN_EXE_agent-bus").to_string()
}

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_cli(addr: Option<&str>, args: &[&str]) -> Run {
    let mut cmd = std::process::Command::new(bin());
    cmd.args(args);
    cmd.env("AGENT_BUS_AGENT", "tester");
    cmd.env("AGENT_BUS_TOKEN", "tok-test");
    cmd.env_remove("AGENT_BUS_SOCK");
    match addr {
        Some(a) => {
            let (h, p) = a.rsplit_once(':').unwrap();
            cmd.env("AGENT_BUS_HOST", h);
            cmd.env("AGENT_BUS_PORT", p);
        }
        None => {
            cmd.env("AGENT_BUS_HOST", "127.0.0.1");
            cmd.env("AGENT_BUS_PORT", "1");
        }
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let out = cmd.output().expect("spawn agent-bus");
    Run {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn msg(seq: u64, sender: &str, ts: Value, payload: Value) -> Value {
    json!({
        "seq": seq, "id": format!("m{seq}"), "sender": sender,
        "ts": ts, "exp": null, "payload": payload,
        "corr_id": null, "reply_to": null,
    })
}

fn cursor(from: u64, next: u64, snap: u64, head: u64, missing: Vec<(u64, u64)>) -> Value {
    let n: u64 = missing.iter().map(|(a, b)| b - a + 1).sum();
    let ranges: Vec<Value> = missing.iter().map(|(a, b)| json!([a, b])).collect();
    json!({
        "topic_seq": head, "snapshot_seq": snap, "from_seq": from,
        "next_seq": next, "oldest_seq": 1, "retained": head,
        "has_more": false, "gap": n > 0, "missing": n,
        "missing_ranges": ranges,
    })
}

fn start_scripted<F>(handler: F) -> String
where
    F: Fn(&Value) -> Value + Send + Sync + 'static,
{
    use std::sync::Arc;
    let handler: Arc<dyn Fn(&Value) -> Value + Send + Sync> = Arc::new(handler);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let h = handler.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let req: Value = match serde_json::from_str(&line) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let req_id = req.get("req_id").cloned().unwrap_or(Value::Null);
                    let mut v = h(&req);
                    if let Some(o) = v.as_object_mut() {
                        o.insert("req_id".to_string(), req_id);
                    }
                    let mut bytes = serde_json::to_vec(&v).unwrap();
                    bytes.push(b'\n');
                    if writer.write_all(&bytes).is_err() {
                        break;
                    }
                    let _ = writer.flush();
                }
            });
        }
    });
    addr
}

fn hello_ok(req: &Value) -> bool {
    req.get("op").and_then(|v| v.as_str()) == Some("hello")
        && req.get("token").and_then(|v| v.as_str()) == Some("tok-test")
}

fn check_hello(req: &Value) -> Option<Value> {
    if req.get("op").and_then(|v| v.as_str()) != Some("hello") {
        return None;
    }
    if hello_ok(req) {
        Some(json!({"ok": true}))
    } else {
        Some(json!({"error": "auth failed"}))
    }
}

#[test]
fn claims_short_json_complete_pinned() {
    let addr = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        if req.get("op").and_then(|v| v.as_str()) == Some("fetch") {
            return json!({
                "ok": true, "topic": "board.build",
                "messages": [
                    msg(1, "alice", Value::Null, json!({"event": "claim", "task": "t1", "files": ["b.rs"]})),
                    msg(2, "bob", Value::Null, json!({"event": "claim", "task": "t2", "files": ["a.rs"]})),
                ],
                "cursor": cursor(0, 2, 2, 2, vec![]),
            });
        }
        json!({"error": "unexpected op"})
    });
    let r = run_cli(Some(&addr), &["claims", "board.build", "--format", "short"]);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(r.stdout.trim(), "a.rs -> bob (t2) ?\nb.rs -> alice (t1) ?");
    let r = run_cli(Some(&addr), &["claims", "--format=json"]);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v["view"], json!("claims"));
    assert_eq!(v["topic"], json!("board.build"));
    assert_eq!(v["advisory"], json!(true));
    assert_eq!(v["atomic_lease"], json!(false));
    assert_eq!(v["held"]["a.rs"]["agent"], json!("bob"));
    assert_eq!(v["held"]["b.rs"]["task"], json!("t1"));
    assert_eq!(v["completeness"]["complete"], json!(true));
    assert_eq!(v["completeness"]["missing"], json!(0));
}

#[test]
fn claims_gap_warns_exits2_with_survivors() {
    let addr = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        json!({
            "ok": true, "topic": "board.build",
            "messages": [msg(3, "alice", Value::Null, json!({"event": "claim", "task": "t", "files": ["k.rs"]}))],
            "cursor": cursor(0, 3, 3, 3, vec![(1, 2)]),
        })
    });
    let r = run_cli(Some(&addr), &["claims", "--format", "short"]);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("k.rs -> alice"), "stdout={}", r.stdout);
    assert!(r.stderr.contains("warning: retention gap"), "stderr={}", r.stderr);
}

#[test]
fn claims_denied_is_error_without_empty_view() {
    let addr = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        json!({"error": "fetch denied: secret.x"})
    });
    let r = run_cli(Some(&addr), &["claims", "secret.x", "--format", "json"]);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.is_empty(), "stdout={}", r.stdout);
    assert!(r.stderr.contains("history catch-up incomplete"), "stderr={}", r.stderr);
}

#[test]
fn claims_stale_filters_by_presence() {
    let addr = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        match req.get("op").and_then(|v| v.as_str()) {
            Some("fetch") => json!({
                "ok": true, "topic": "board.build",
                "messages": [
                    msg(1, "fresh", Value::Null, json!({"event": "claim", "task": "t", "files": ["new.rs"]})),
                    msg(2, "gone", Value::Null, json!({"event": "claim", "task": "t", "files": ["old.rs"]})),
                ],
                "cursor": cursor(0, 2, 2, 2, vec![]),
            }),
            Some("agents") => json!({"ok": true, "agents": {"fresh": {"age_s": 5.0, "online": true}}}),
            _ => json!({"error": "unexpected op"}),
        }
    });
    let r = run_cli(Some(&addr), &["claims", "--format", "short", "--stale", "30m"]);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("old.rs -> gone"), "stdout={}", r.stdout);
    assert!(!r.stdout.contains("new.rs"), "stdout={}", r.stdout);
    let r = run_cli(Some(&addr), &["claims", "--format=json", "--stale=1m"]);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert!(v["held"].get("old.rs").is_some());
    assert_eq!(v["stale_filter"]["max_age_s"], json!(60.0));
}

#[test]
fn claims_bad_stale_exits1_before_fetch() {
    let r = run_cli(None, &["claims", "--stale", "bogus"]);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.contains("bad --stale value"), "stderr={}", r.stderr);
}

#[test]
fn packets_short_json_window_pinned() {
    let addr = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        json!({
            "ok": true, "topic": "board.announce",
            "messages": [
                msg(1, "a", json!(1.0), json!("[claim] packet=P2")),
                msg(2, "b", json!(2.0), json!("[claim] packet=P1")),
                msg(3, "c", json!(3.0), json!("[packet-ready] R1")),
                msg(4, "d", json!(4.0), json!("[done] packet=D1")),
            ],
            "cursor": cursor(0, 4, 4, 4, vec![]),
        })
    });
    let r = run_cli(Some(&addr), &["packets", "--format", "short", "--tail", "60"]);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("P1 <- b (seq 2)"), "stdout={}", r.stdout);
    assert!(r.stdout.contains("P2 <- a (seq 1)"), "stdout={}", r.stdout);
    assert!(r.stdout.contains("ready unclaimed: R1"), "stdout={}", r.stdout);
    assert!(r.stdout.contains("done in window: D1"), "stdout={}", r.stdout);
    let r = run_cli(Some(&addr), &["packets", "board.announce", "--format=json", "--tail=2"]);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v["view"], json!("packets"));
    assert!(v["open"].as_object().unwrap().is_empty());
    assert_eq!(v["ready"], json!(["R1"]));
    assert_eq!(v["done"], json!(["D1"]));
    assert_eq!(v["window"]["tail"], json!(2));
}

#[test]
fn packets_multi_topic_merges_by_ts_not_atomic() {
    let addr = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        let topic = req.get("topic").and_then(|v| v.as_str()).unwrap_or("");
        match topic {
            "board.announce" => {
                let mut m = msg(1, "a", json!(10.0), json!("[claim] packet=PX"));
                m["id"] = json!("announce-1");
                json!({
                    "ok": true, "topic": topic,
                    "messages": [m],
                    "cursor": cursor(0, 1, 1, 1, vec![]),
                })
            }
            "board.other" => {
                let mut m = msg(1, "b", json!(20.0), json!("[claim] packet=PX"));
                m["id"] = json!("other-1");
                json!({
                    "ok": true, "topic": topic,
                    "messages": [m],
                    "cursor": cursor(0, 1, 1, 1, vec![]),
                })
            }
            _ => json!({"error": "unknown topic"}),
        }
    });
    let r = run_cli(
        Some(&addr),
        &["packets", "board.announce", "board.other", "--format", "short"],
    );
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("PX <- b (seq 1@board.other)"), "stdout={}", r.stdout);
    assert!(r.stderr.contains("not atomic"), "stderr={}", r.stderr);
}

#[test]
fn packets_gap_in_window_exits2_denied_no_view() {
    let addr = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        json!({
            "ok": true, "topic": "board.announce",
            "messages": [msg(60, "a", json!(60.0), json!("[claim] packet=PW"))],
            "cursor": cursor(0, 60, 60, 60, vec![(1, 59)]),
        })
    });
    let r = run_cli(Some(&addr), &["packets", "--tail", "60", "--format", "short"]);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.contains("PW <- a"), "stdout={}", r.stdout);
    assert!(r.stderr.contains("retention gap within the tail window"), "stderr={}", r.stderr);

    let denied = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        json!({"error": "fetch denied: board.announce"})
    });
    let r = run_cli(Some(&denied), &["packets", "--format", "json"]);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.is_empty(), "stdout={}", r.stdout);
}

#[test]
fn claims_packets_usage_validation_before_network() {
    for args in [
        vec!["claims", "--format", "xml"],
        vec!["claims", "board.*"],
        vec!["claims", "a", "b"],
        vec!["claims", "--bogus"],
        vec!["claims", "--timeout", "0"],
        vec!["packets", "--tail", "0"],
        vec!["packets", "--tail", "bogus"],
        vec!["packets", "--format", "yaml"],
        vec!["packets", "board.*"],
        vec!["packets", "--bogus"],
    ] {
        let r = run_cli(None, &args);
        assert_eq!(r.status, 2, "args={args:?} stdout={} stderr={}", r.stdout, r.stderr);
        assert!(r.stdout.is_empty(), "args={args:?} stdout={}", r.stdout);
    }
    // `--` terminator keeps dash-led topics literal (rejected as pattern-free
    // but unknown exact topics fail at fetch, not usage).
    let addr = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        json!({"error": "fetch denied: --weird"})
    });
    let r = run_cli(Some(&addr), &["claims", "--", "--weird"]);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("history catch-up incomplete"), "stderr={}", r.stderr);
}

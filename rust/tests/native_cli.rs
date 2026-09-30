//! Native CLI tests: `agent-bus` binary against scripted in-process fixtures.
//!
//! No live broker, no Python: each test starts a loopback JSON-lines fixture
//! speaking the transitional wire (`hello` + scripted ops) and runs the real
//! binary (`CARGO_BIN_EXE_agent-bus`) with `AGENT_BUS_*` env pointed at it.
//! Covers pinned-snapshot pagination, retention-gap handling, stdin payload
//! semantics, short renderers, and the required negatives (auth refusal,
//! malformed/partial responses, snapshot drift, failed-RPC exit codes,
//! explicit unsupported-command failures). The closing RPC-bounds section
//! exercises `wire::Client` directly against the same fixtures for finite
//! deadlines, bounded reply frames, and strict `req_id` validation.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agent_bus::wire::{Client, CLIENT_CONNECT_TIMEOUT, CLIENT_RESP_LIMIT, CLIENT_RPC_TIMEOUT};
use serde_json::{json, Value};

fn bin() -> String {
    env!("CARGO_BIN_EXE_agent-bus").to_string()
}

/// What the fixture sends back for one request line.
enum ScriptResp {
    Json(Value),
    Raw(String),
    /// Close the connection without any response frame (partial response).
    Close,
    /// Sleep without replying (silent server), then close.
    Sleep(Duration),
    /// Send bytes without a newline, flush, then sleep without completing.
    Partial(String, Duration),
    /// Slow-drip `chunk` `count` times with `gap` between writes, no newline.
    Drip {
        chunk: Vec<u8>,
        count: usize,
        gap: Duration,
    },
}

struct Fixture {
    addr: String,
    received: Arc<Mutex<Vec<Value>>>,
}

/// Start a fixture whose handler maps each parsed request to a response.
/// `hello` auth is the handler's job; `req_id` is echoed on JSON replies.
fn start_scripted<F>(handler: F) -> Fixture
where
    F: Fn(&Value) -> ScriptResp + Send + Sync + 'static,
{
    let handler: Arc<dyn Fn(&Value) -> ScriptResp + Send + Sync> = Arc::new(handler);
    let received: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let got = received.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let h = handler.clone();
            let got = got.clone();
            std::thread::spawn(move || serve_one(stream, &h, &got));
        }
    });
    Fixture { addr, received: received.clone() }
}

fn serve_one(
    stream: TcpStream,
    handler: &Arc<dyn Fn(&Value) -> ScriptResp + Send + Sync>,
    received: &Arc<Mutex<Vec<Value>>>,
) {
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
        received.lock().unwrap().push(req.clone());
        let req_id = req.get("req_id").cloned().unwrap_or(Value::Null);
        match handler(&req) {
            ScriptResp::Json(mut v) => {
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
            ScriptResp::Raw(s) => {
                if writer.write_all(s.as_bytes()).is_err() {
                    break;
                }
                let _ = writer.flush();
            }
            ScriptResp::Close => break,
            ScriptResp::Sleep(d) => {
                std::thread::sleep(d);
                break;
            }
            ScriptResp::Partial(prefix, d) => {
                if writer.write_all(prefix.as_bytes()).is_err() {
                    break;
                }
                let _ = writer.flush();
                std::thread::sleep(d);
                break;
            }
            ScriptResp::Drip { chunk, count, gap } => {
                for _ in 0..count {
                    if writer.write_all(&chunk).is_err() {
                        break;
                    }
                    let _ = writer.flush();
                    std::thread::sleep(gap);
                }
                break;
            }
        }
    }
}

fn hello_ok(req: &Value) -> bool {
    req.get("op").and_then(|v| v.as_str()) == Some("hello")
        && req.get("token").and_then(|v| v.as_str()) == Some("tok-test")
        && req.get("agent").and_then(|v| v.as_str()) == Some("tester")
}

fn check_hello(req: &Value) -> Option<ScriptResp> {
    if req.get("op").and_then(|v| v.as_str()) != Some("hello") {
        return None;
    }
    if hello_ok(req) {
        Some(ScriptResp::Json(json!({"ok": true, "agent": "tester"})))
    } else {
        Some(ScriptResp::Json(json!({"error": "auth failed"})))
    }
}

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_cli(
    fx: Option<&Fixture>,
    args: &[&str],
    stdin_data: Option<&str>,
    drop_token: bool,
) -> Run {
    let mut cmd = std::process::Command::new(bin());
    cmd.args(args);
    cmd.env("AGENT_BUS_AGENT", "tester");
    if drop_token {
        cmd.env_remove("AGENT_BUS_TOKEN");
    } else {
        cmd.env("AGENT_BUS_TOKEN", "tok-test");
    }
    // TCP-only fixtures: an ambient `AGENT_BUS_SOCK` must never divert
    // these preserved TCP paths to Unix. Unix CLI coverage lives in
    // `tests/unix_transport.rs` with explicit `AGENT_BUS_SOCK`.
    cmd.env_remove("AGENT_BUS_SOCK");
    match fx {
        Some(f) => {
            let (host, port) = f.addr.rsplit_once(':').unwrap();
            cmd.env("AGENT_BUS_HOST", host);
            cmd.env("AGENT_BUS_PORT", port);
        }
        None => {
            // Usage/unsupported paths must fail before connecting; point at a
            // dead port so any unexpected dial fails fast, not against live.
            cmd.env("AGENT_BUS_HOST", "127.0.0.1");
            cmd.env("AGENT_BUS_PORT", "1");
        }
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    if stdin_data.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn agent-bus");
    if let Some(data) = stdin_data {
        use std::io::Write;
        // EPIPE-tolerant: a CLI that exits before reading stdin (usage error)
        // still yields assertion-worthy output below.
        let _ = child.stdin.as_mut().unwrap().write_all(data.as_bytes());
    }
    let out = child.wait_with_output().expect("wait agent-bus");
    Run {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn ops(fx: &Fixture, op: &str) -> Vec<Value> {
    fx.received
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.get("op").and_then(|v| v.as_str()) == Some(op))
        .cloned()
        .collect()
}

fn msg(seq: u64, payload: Value) -> Value {
    json!({
        "seq": seq, "id": format!("m{seq}"), "sender": "alice",
        "ts": 1700000000.0, "exp": null, "payload": payload,
        "corr_id": null, "reply_to": null,
    })
}

fn cursor(from: u64, next: u64, snap: u64, head: u64, has_more: bool, missing: Vec<(u64, u64)>) -> Value {
    let n: u64 = missing.iter().map(|(a, b)| b - a + 1).sum();
    let ranges: Vec<Value> = missing.iter().map(|(a, b)| json!([a, b])).collect();
    json!({
        "topic_seq": head, "snapshot_seq": snap, "from_seq": from,
        "next_seq": next, "oldest_seq": 1, "retained": head,
        "has_more": has_more, "gap": n > 0, "missing": n,
        "missing_ranges": ranges,
    })
}

// ---------------------------------------------------------------------------
// show: pinned snapshot pagination + gap handling
// ---------------------------------------------------------------------------

#[test]
fn show_pins_snapshot_across_pages() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        let from = req.get("from_seq").and_then(|v| v.as_u64()).unwrap_or(999);
        match from {
            0 => ScriptResp::Json(json!({
                "ok": true, "topic": "board.build",
                "messages": [msg(1, json!({"n": 1})), msg(2, json!({"n": 2}))],
                "cursor": cursor(0, 2, 5, 5, true, vec![]),
            })),
            2 => {
                // Second page must pin the first snapshot, not re-snapshot.
                if req.get("until_seq").and_then(|v| v.as_u64()) != Some(5) {
                    return ScriptResp::Json(json!({"error": "fixture: until_seq not pinned"}));
                }
                ScriptResp::Json(json!({
                    "ok": true, "topic": "board.build",
                    "messages": [msg(3, json!({"n": 3})), msg(4, json!({"n": 4})), msg(5, json!({"n": 5}))],
                    "cursor": cursor(2, 5, 5, 5, false, vec![]),
                }))
            }
            _ => ScriptResp::Json(json!({"error": "fixture: unexpected from_seq"})),
        }
    });
    let r = run_cli(Some(&fx), &["show", "board.build", "--since-seq", "0", "--format", "json"], None, false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines.len(), 5, "stdout={}", r.stdout);
    for (i, line) in lines.iter().enumerate() {
        let fr: Value = serde_json::from_str(line).unwrap();
        assert_eq!(fr["event"], json!("msg"));
        assert_eq!(fr["topic"], json!("board.build"));
        assert_eq!(fr["msg"]["seq"], json!((i + 1) as u64));
    }
    assert!(r.stderr.contains("note: snapshot on 'board.build' processed through 5"), "stderr={}", r.stderr);
    assert_eq!(ops(&fx, "fetch").len(), 2);
}

#[test]
fn show_gap_warns_and_exits_2_with_survivors() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({
            "ok": true, "topic": "t",
            "messages": [msg(3, json!("kept"))],
            "cursor": cursor(0, 3, 3, 3, false, vec![(1, 2)]),
        }))
    });
    let r = run_cli(Some(&fx), &["show", "t", "--since-seq", "0", "--format", "json"], None, false);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines.len(), 1);
    let fr: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(fr["msg"]["seq"], json!(3));
    assert!(r.stderr.contains("warning: retention gap"), "stderr={}", r.stderr);
    assert!(r.stderr.contains("next: --since-seq 3"), "stderr={}", r.stderr);
}

#[test]
fn show_snapshot_drift_fails_incomplete() {
    // Pinned snapshot must hold: a page answering with a different snapshot
    // is an incomplete catch-up, never silently accepted.
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        let from = req.get("from_seq").and_then(|v| v.as_u64()).unwrap_or(999);
        match from {
            0 => ScriptResp::Json(json!({
                "ok": true, "topic": "t",
                "messages": [msg(1, json!(1))],
                "cursor": cursor(0, 1, 5, 5, true, vec![]),
            })),
            _ => ScriptResp::Json(json!({
                "ok": true, "topic": "t",
                "messages": [msg(2, json!(2)), msg(3, json!(3)), msg(4, json!(4)), msg(5, json!(5)), msg(6, json!(6))],
                "cursor": cursor(1, 6, 6, 6, false, vec![]),
            })),
        }
    });
    let r = run_cli(Some(&fx), &["show", "t", "--since-seq", "0", "--format", "json"], None, false);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("invalid history cursor"), "stderr={}", r.stderr);
    assert!(r.stderr.contains("resume with --since-seq 1"), "stderr={}", r.stderr);
}

#[test]
fn show_reordered_messages_fail_incomplete() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({
            "ok": true, "topic": "t",
            "messages": [msg(2, json!(2)), msg(1, json!(1))],
            "cursor": cursor(0, 2, 2, 2, false, vec![]),
        }))
    });
    let r = run_cli(Some(&fx), &["show", "t", "--since-seq", "0", "--format", "json"], None, false);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("invalid history message order"), "stderr={}", r.stderr);
    assert!(r.stdout.is_empty(), "no partial frames on invalid page: {}", r.stdout);
}

#[test]
fn show_fetch_denied_is_incomplete_with_resume_cursor() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"error": "fetch denied: secret.x"}))
    });
    let r = run_cli(
        Some(&fx),
        &["show", "secret.x", "--since-seq", "4", "--format", "json"],
        None,
        false,
    );
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("history catch-up incomplete on 'secret.x'"), "stderr={}", r.stderr);
    assert!(r.stderr.contains("fetch denied"), "stderr={}", r.stderr);
    assert!(r.stderr.contains("resume with --since-seq 4"), "stderr={}", r.stderr);
}

#[test]
fn show_sender_filter_keeps_pagination_cursor() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        let mut m1 = msg(1, json!("a"));
        m1["sender"] = json!("alice");
        let mut m2 = msg(2, json!("b"));
        m2["sender"] = json!("bob");
        ScriptResp::Json(json!({
            "ok": true, "topic": "t", "messages": [m1, m2],
            "cursor": cursor(0, 2, 2, 2, false, vec![]),
        }))
    });
    let r = run_cli(
        Some(&fx),
        &["show", "t", "--since-seq", "0", "--format", "payload", "--sender", "bob"],
        None,
        false,
    );
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(r.stdout.lines().count(), 1);
    assert!(r.stdout.contains("\"b\""), "stdout={}", r.stdout);
    assert!(r.stderr.contains("next: --since-seq 2"), "stderr={}", r.stderr);
}

#[test]
fn show_without_since_seq_is_explicitly_unsupported() {
    for args in [&["show", "t"][..], &["show", "t", "--tail", "5"][..], &["show", "t", "3"][..]] {
        let r = run_cli(None, args, None, false);
        assert_eq!(r.status, 2, "args={args:?} stdout={} stderr={}", r.stdout, r.stderr);
        assert!(
            r.stderr.contains("--since-seq") || r.stderr.contains("subscribe"),
            "args={args:?} stderr={}",
            r.stderr
        );
    }
    // The --tail rejection now names the in-slice replacement.
    let r = run_cli(None, &["show", "t", "--tail", "5"], None, false);
    assert!(r.stderr.contains("--last N"), "stderr={}", r.stderr);
}

#[test]
fn show_last_prints_tail_of_snapshot() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        let from = req.get("from_seq").and_then(|v| v.as_u64()).unwrap_or(999);
        match from {
            0 => ScriptResp::Json(json!({
                "ok": true, "topic": "t",
                "messages": [msg(1, json!({"n": 1})), msg(2, json!({"n": 2})), msg(3, json!({"n": 3}))],
                "cursor": cursor(0, 3, 5, 5, true, vec![]),
            })),
            3 => ScriptResp::Json(json!({
                "ok": true, "topic": "t",
                "messages": [msg(4, json!({"n": 4})), msg(5, json!({"n": 5}))],
                "cursor": cursor(3, 5, 5, 5, false, vec![]),
            })),
            _ => ScriptResp::Json(json!({"error": "fixture: unexpected from_seq"})),
        }
    });
    let r = run_cli(Some(&fx), &["show", "t", "--last", "2", "--format", "json"], None, false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    // Exactly the last two rows across the page boundary; earlier rows
    // are drained (cursor advances) but not printed.
    assert_eq!(r.stdout.lines().count(), 2, "stdout={}", r.stdout);
    assert!(r.stdout.contains(r#""n":4"#), "stdout={}", r.stdout);
    assert!(r.stdout.contains(r#""n":5"#), "stdout={}", r.stdout);
    assert!(!r.stdout.contains(r#""n":1"#), "stdout={}", r.stdout);
    assert!(r.stderr.contains("next: --since-seq 5"), "stderr={}", r.stderr);
    // --last drains from history: the first fetch starts at 0.
    let fetches = ops(&fx, "fetch");
    assert!(!fetches.is_empty());
    assert_eq!(fetches[0].get("from_seq").and_then(|v| v.as_u64()), Some(0));
    // A window larger than history prints everything, no padding.
    let r = run_cli(Some(&fx), &["show", "t", "--last", "99", "--format", "json"], None, false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(r.stdout.lines().count(), 5, "stdout={}", r.stdout);
}

#[test]
fn show_last_full_tail_with_older_gap_exits_0() {
    // Retention drops oldest rows, so a fully-populated --last
    // tail is the true tail: exit 0 with the warning retained.
    // A --since-seq resume over the same gap still exits 2.
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({
            "ok": true, "topic": "t",
            "messages": [msg(3, json!({"n": 3})), msg(4, json!({"n": 4})), msg(5, json!({"n": 5}))],
            "cursor": cursor(0, 5, 5, 5, false, vec![(1, 2)]),
        }))
    });
    let r = run_cli(Some(&fx), &["show", "t", "--last", "2", "--format", "json"], None, false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(r.stdout.lines().count(), 2, "stdout={}", r.stdout);
    assert!(r.stdout.contains(r#""n":4"#), "stdout={}", r.stdout);
    assert!(r.stdout.contains(r#""n":5"#), "stdout={}", r.stdout);
    assert!(r.stderr.contains("warning: retention gap"), "stderr={}", r.stderr);
    assert!(r.stderr.contains("next: --since-seq 5"), "stderr={}", r.stderr);
    // Sender-filtered full tail: same rule (all fixture rows are alice).
    let r = run_cli(
        Some(&fx),
        &["show", "t", "--last", "2", "--sender", "alice", "--format", "json"],
        None,
        false,
    );
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(r.stdout.lines().count(), 2, "stdout={}", r.stdout);
}

#[test]
fn show_last_short_tail_with_gap_exits_2() {
    // A short tail with expired history is genuinely incomplete:
    // some of the requested rows are gone, so exit 2 stays.
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({
            "ok": true, "topic": "t",
            "messages": [msg(3, json!({"n": 3}))],
            "cursor": cursor(0, 3, 3, 3, false, vec![(1, 2)]),
        }))
    });
    let r = run_cli(Some(&fx), &["show", "t", "--last", "99", "--format", "json"], None, false);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(r.stdout.lines().count(), 1, "stdout={}", r.stdout);
    assert!(r.stderr.contains("warning: retention gap"), "stderr={}", r.stderr);
}

#[test]
fn show_rejection_paths_name_last_alternative() {
    // Every show cursor rejection must name the in-slice tail
    // equivalent, not only --since-seq/--tail: agents hitting
    // these errors otherwise never learn --last exists.
    for args in [&["show", "t", "--since"][..], &["show", "a", "b"][..]] {
        let r = run_cli(None, args, None, false);
        assert_eq!(r.status, 2, "args={args:?} stdout={} stderr={}", r.stdout, r.stderr);
        assert!(r.stderr.contains("--last N"), "args={args:?} stderr={}", r.stderr);
    }
}

#[test]
fn show_last_conflicts_with_since_seq() {
    let r = run_cli(None, &["show", "t", "--since-seq", "3", "--last", "2"], None, false);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("not both"), "stderr={}", r.stderr);
}

#[test]
fn show_last_rejects_bad_values() {
    for v in ["0", "-3", "abc"] {
        let r = run_cli(None, &["show", "t", "--last", v], None, false);
        assert_eq!(r.status, 2, "v={v} stdout={} stderr={}", r.stdout, r.stderr);
        assert!(r.stderr.contains("bad --last"), "v={v} stderr={}", r.stderr);
    }
}

#[test]
fn show_equals_form_matches_space_form() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        let from = req.get("from_seq").and_then(|v| v.as_u64()).unwrap_or(999);
        if from != 0 {
            return ScriptResp::Json(json!({"error": "fixture: unexpected from_seq"}));
        }
        ScriptResp::Json(json!({
            "ok": true, "topic": "t",
            "messages": [msg(1, json!({"n": 1}))],
            "cursor": cursor(0, 1, 1, 1, false, vec![]),
        }))
    });
    let r = run_cli(
        Some(&fx),
        &["show", "t", "--since-seq=0", "--format=json"],
        None,
        false,
    );
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(r.stdout.lines().count(), 1, "stdout={}", r.stdout);
    // Empty and bad values keep space-form validation (exit 2, no dial).
    for args in [
        vec!["show", "t", "--since-seq=", "--format=json"],
        vec!["show", "t", "--since-seq=abc"],
        vec!["show", "t", "--last=0"],
    ] {
        let r = run_cli(None, &args, None, false);
        assert_eq!(
            r.status, 2,
            "args={args:?} stdout={} stderr={}",
            r.stdout, r.stderr
        );
        assert!(
            r.stderr.contains("bad --since-seq") || r.stderr.contains("bad --last"),
            "args={args:?} stderr={}",
            r.stderr
        );
    }
}

// ---------------------------------------------------------------------------
// post: stdin JSON/text semantics, durable, refused RPC
// ---------------------------------------------------------------------------

#[test]
fn post_stdin_json_parses_and_sends_durable() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true, "id": "m1", "seq": 7}))
    });
    let r = run_cli(
        Some(&fx),
        &["post", "board.build", "-", "--durable"],
        Some("{\"note\":\"hi\"}"),
        false,
    );
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let resp: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(resp["seq"], json!(7));
    let posts = ops(&fx, "post");
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0]["topic"], json!("board.build"));
    assert_eq!(posts[0]["payload"], json!({"note": "hi"}));
    assert_eq!(posts[0]["durable"], json!(true));
}

#[test]
fn post_stdin_plain_text_preserved_verbatim() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true, "id": "m2", "seq": 8}))
    });
    let r = run_cli(Some(&fx), &["post", "t", "-"], Some("just text"), false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let posts = ops(&fx, "post");
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0]["payload"], json!("just text"));
}

#[test]
fn post_flags_reach_the_wire() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true, "id": "m3", "seq": 1}))
    });
    let r = run_cli(
        Some(&fx),
        &["post", "t", "{\"a\":1}", "--ttl-ms", "60000", "--corr", "c1", "--reply-to", "inbox.x"],
        None,
        false,
    );
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let posts = ops(&fx, "post");
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0]["payload"], json!({"a": 1}));
    assert_eq!(posts[0]["ttl_ms"], json!(60000.0));
    assert_eq!(posts[0]["corr_id"], json!("c1"));
    assert_eq!(posts[0]["reply_to"], json!("inbox.x"));
}

#[test]
fn post_equals_form_reaches_the_wire() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true, "id": "m3", "seq": 1}))
    });
    let r = run_cli(
        Some(&fx),
        &["post", "t", "{\"a\":1}", "--ttl-ms=60000", "--corr=c1"],
        None,
        false,
    );
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let posts = ops(&fx, "post");
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0]["payload"], json!({"a": 1}));
    assert_eq!(posts[0]["ttl_ms"], json!(60000.0));
    assert_eq!(posts[0]["corr_id"], json!("c1"));
}

#[test]
fn equals_expansion_stops_at_double_dash_terminator() {
    // `--opt=value` splits before `--` (argparse parity) but stays literal
    // after it: `kv-del -- --foo=bar` must forward the key exactly
    // `--foo=bar`, never split into `--foo` + `bar` (which would error as
    // an unknown option or the wrong key). Preserves Main's equals-form
    // work (1214/15) with the `--` terminator fix.
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true, "key": "--foo=bar", "found": false}))
    });
    let r = run_cli(Some(&fx), &["kv-del", "--", "--foo=bar"], None, false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let sent = ops(&fx, "kv_del");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["key"], json!("--foo=bar"), "key split at =: {sent:?}");
    // Before `--`, equals still splits (space-form parity).
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true, "id": "m", "seq": 1}))
    });
    let r = run_cli(
        Some(&fx),
        &["post", "t", "hi", "--ttl-ms=1000"],
        None,
        false,
    );
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(ops(&fx, "post")[0]["ttl_ms"], json!(1000.0));
}

#[test]
fn post_claim_builds_coordination_payload() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true, "id": "m4", "seq": 2}))
    });
    let r = run_cli(
        Some(&fx),
        &["post", "board.build", "--claim", "a.rs,b.rs", "--task", "t1"],
        None,
        false,
    );
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let posts = ops(&fx, "post");
    assert_eq!(posts.len(), 1);
    assert_eq!(
        posts[0]["payload"],
        json!({"from": "tester", "event": "claim", "task": "t1", "files": ["a.rs", "b.rs"]})
    );
}

#[test]
fn post_refused_exits_1_without_stdout() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"error": "publish denied: other.x"}))
    });
    let r = run_cli(Some(&fx), &["post", "other.x", "hi"], None, false);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.is_empty(), "stdout={}", r.stdout);
    assert!(r.stderr.contains("publish denied"), "stderr={}", r.stderr);
}

#[test]
fn post_payload_note_claim_are_mutually_exclusive() {
    let r = run_cli(None, &["post", "t", "x", "--note", "y"], None, false);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("mutually exclusive"), "stderr={}", r.stderr);
}

// ---------------------------------------------------------------------------
// heartbeat + agents
// ---------------------------------------------------------------------------

#[test]
fn heartbeat_sends_status_and_prints_reply() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true}))
    });
    let r = run_cli(Some(&fx), &["heartbeat", "deep work"], None, false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let beats = ops(&fx, "heartbeat");
    assert_eq!(beats.len(), 1);
    assert_eq!(beats[0]["status"], json!("deep work"));
}

#[test]
fn agents_short_orders_fresh_first_with_stale_marker() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({
            "ok": true,
            "agents": {
                "amy": {"status": "{\"status\":\"deep work\"}", "age_s": 700.0, "online": false},
                "bob": {"status": "online", "age_s": 5.0, "online": true},
            }
        }))
    });
    let r = run_cli(Some(&fx), &["agents", "--format", "short"], None, false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "bob 5s online\namy 12m deep work (stale)\n");
}

#[test]
fn agents_filtered_flags_are_explicitly_unsupported() {
    for flag in ["--hide-stale", "--limit", "--sort-name"] {
        let args: Vec<&str> = if flag == "--limit" {
            vec!["agents", "--limit", "3"]
        } else {
            vec!["agents", flag]
        };
        let r = run_cli(None, &args, None, false);
        assert_eq!(r.status, 2, "flag={flag} stdout={} stderr={}", r.stdout, r.stderr);
        assert!(r.stderr.contains("not supported"), "flag={flag} stderr={}", r.stderr);
    }
}

// ---------------------------------------------------------------------------
// kv-get / kv-put / kv-list
// ---------------------------------------------------------------------------

#[test]
fn kv_get_short_missing_exits_1() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true, "found": false}))
    });
    let r = run_cli(Some(&fx), &["kv-get", "k1", "--format", "short"], None, false);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("key 'k1' not found"), "stderr={}", r.stderr);
}

#[test]
fn kv_get_json_found_prints_reply() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true, "found": true, "value": {"a": 1}}))
    });
    let r = run_cli(Some(&fx), &["kv-get", "k1"], None, false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let resp: Value = serde_json::from_str(r.stdout.trim()).unwrap();
    assert_eq!(resp["value"], json!({"a": 1}));
}

#[test]
fn kv_put_stdin_sends_value_with_durable() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true, "key": "k1"}))
    });
    let r = run_cli(Some(&fx), &["kv-put", "k1", "-", "--durable"], Some("v"), false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    let puts = ops(&fx, "kv_put");
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0]["key"], json!("k1"));
    assert_eq!(puts[0]["value"], json!("v"));
    assert_eq!(puts[0]["durable"], json!(true));
}

#[test]
fn kv_delete_forwards_exact_key_and_durable_flag_and_preserves_found() {
    for (key, found, durable) in [("ctx.\u{03bb} / note", true, true), ("--help", false, false)] {
        let fx = start_scripted(move |req| {
            if let Some(r) = check_hello(req) { return r; }
            ScriptResp::Json(json!({"ok":true, "key":key, "found":found}))
        });
        let args = if durable { vec!["kv-del", key, "--durable"] }
            else { vec!["kv-del", "--", key] };
        let r = run_cli(Some(&fx), &args, None, false);
        assert_eq!(r.status, 0, "{} {}", r.stdout, r.stderr);
        let reply: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(reply["key"], key);
        assert_eq!(reply["found"], found);
        let sent = ops(&fx, "kv_del");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["key"], key);
        assert_eq!(sent[0].get("durable"), if durable {Some(&json!(true))} else {None});
    }
}

#[test]
fn kv_delete_refuses_malformed_receipts_without_success_output() {
    for reply in [
        json!({"ok":true, "key":"ctx.x"}),
        json!({"ok":true, "key":"ctx.x", "found":"yes"}),
        json!({"ok":true, "key":"ctx.other", "found":true}),
    ] {
        let fx = start_scripted(move |req| {
            if let Some(r) = check_hello(req) { return r; }
            ScriptResp::Json(reply.clone())
        });
        let r = run_cli(Some(&fx), &["kv-del", "ctx.x"], None, false);
        assert_eq!(r.status, 1);
        assert!(r.stdout.is_empty());
        assert!(r.stderr.contains("invalid kv-del receipt"));
        assert_eq!(ops(&fx, "kv_del").len(), 1);
    }
}

#[test]
fn kv_delete_denial_and_lost_receipt_are_not_retried() {
    for close in [false, true] {
        let fx = start_scripted(move |req| {
            if let Some(r) = check_hello(req) { return r; }
            if close { ScriptResp::Close }
            else { ScriptResp::Json(json!({"error":"kv_del denied"})) }
        });
        let r = run_cli(Some(&fx), &["kv-del", "ctx.x", "--durable"], None, false);
        assert_eq!(r.status, 1);
        assert!(r.stdout.is_empty());
        assert_eq!(ops(&fx, "kv_del").len(), 1);
        assert!(!r.stderr.contains("tok-test"));
    }
}

#[test]
fn kv_delete_usage_and_help_need_no_connection() {
    for args in [vec!["kv-del"], vec!["kv-del", "a", "b"], vec!["kv-del", "a", "--ttl-ms", "1"]] {
        let r = run_cli(None, &args, None, true);
        assert_eq!(r.status, 2, "{args:?}: {}", r.stderr);
    }
    let r = run_cli(None, &["kv-del", "--help"], None, true);
    assert_eq!(r.status, 0);
    assert!(r.stdout.contains("kv-del KEY [--durable]"));
}

#[test]
fn kv_list_values_short_fans_out_per_key() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        let op = req.get("op").and_then(|v| v.as_str()).unwrap_or("");
        match op {
            "kv_list" => ScriptResp::Json(json!({"ok": true, "keys": ["a", "b"]})),
            "kv_get" => {
                if req.get("key").and_then(|v| v.as_str()) == Some("a") {
                    ScriptResp::Json(json!({"ok": true, "found": true, "value": "x"}))
                } else {
                    ScriptResp::Json(json!({"ok": true, "found": false}))
                }
            }
            _ => ScriptResp::Json(json!({"error": "fixture: unexpected op"})),
        }
    });
    let r = run_cli(Some(&fx), &["kv-list", "--values", "--format", "short"], None, false);
    assert_eq!(r.status, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "a = x\nb = <not-found>\n");
    assert_eq!(ops(&fx, "kv_get").len(), 2);
}

// ---------------------------------------------------------------------------
// negatives: auth, malformed/partial responses, unsupported, env
// ---------------------------------------------------------------------------

#[test]
fn auth_refusal_exits_1_without_leaking_token() {
    let fx = start_scripted(|_| ScriptResp::Json(json!({"error": "auth failed"})));
    let r = run_cli(Some(&fx), &["heartbeat"], None, false);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.is_empty(), "stdout={}", r.stdout);
    assert!(
        r.stderr.contains("connect failed") || r.stderr.contains("auth"),
        "stderr={}",
        r.stderr
    );
    assert!(!r.stderr.contains("tok-test"), "token leaked: {}", r.stderr);
    assert!(!r.stdout.contains("tok-test"), "token leaked to stdout");
}

#[test]
fn malformed_response_line_fails_cleanly() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Raw("not-json\n".to_string())
    });
    let r = run_cli(Some(&fx), &["post", "t", "hi"], None, false);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(!r.stderr.contains("panick"), "must not panic: {}", r.stderr);
    assert!(r.stderr.contains("error:"), "stderr={}", r.stderr);
    assert!(r.stdout.is_empty(), "stdout={}", r.stdout);
}

#[test]
fn closed_connection_fails_cleanly() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Close
    });
    let r = run_cli(Some(&fx), &["heartbeat"], None, false);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(!r.stderr.contains("panick"), "must not panic: {}", r.stderr);
    assert!(r.stderr.contains("error:"), "stderr={}", r.stderr);
}

#[test]
fn unsupported_verbs_fail_explicitly_without_python() {
    // `ping` landed (see tests/idempotency.rs); `sub`/`subs`/
    // `unsubscribe` landed (see tests/subscriptions.rs); `token-issue`/
    // `token-revoke`/`token-claim` landed (see tests/token_admin.rs);
    // `art-put`/`art-get` landed (see tests/artifacts.rs); `request`/
    // `reply` landed (see tests/request_reply.rs); `claims`/`packets`
    // landed (see tests/coord_views.rs); none belong here.
    // `claims`/`packets` are supported verbs now: `--help` exits 0 with
    // usage (never "not supported"), and bad options exit 2 with usage.
    for cmd in ["claims", "packets"] {
        let r = run_cli(None, &[cmd, "--help"], None, false);
        assert_eq!(r.status, 0, "cmd={cmd} stdout={} stderr={}", r.stdout, r.stderr);
        assert!(r.stdout.contains("usage:"), "cmd={cmd} stdout={}", r.stdout);
        assert!(!r.stderr.contains("not supported"), "cmd={cmd} stderr={}", r.stderr);
        assert!(!r.stdout.contains("not supported"), "cmd={cmd} stdout={}", r.stdout);
    }
}

#[test]
fn unsupported_verbs_name_an_alternative() {
    // Every unsupported verb must point at the closest in-slice
    // alternative (or state plainly that none exists); a bare
    // "not supported" strands newcomers mid-round.
    // (`sub`/`subs` are now supported; see tests/subscriptions.rs.
    // `token-*` are now supported; see tests/token_admin.rs.
    // `art-put`/`art-get` are now supported; see tests/artifacts.rs.
    // `request`/`reply` are now supported; see tests/request_reply.rs.
    // `claims`/`packets` are now supported; see tests/coord_views.rs.)
    for (cmd, hint) in [
        ("whoami", "$AGENT_BUS_AGENT"),
    ] {
        let r = run_cli(None, &[cmd], None, false);
        assert_eq!(r.status, 2, "cmd={cmd} stdout={} stderr={}", r.stdout, r.stderr);
        assert!(r.stderr.contains(hint), "cmd={cmd} stderr={}", r.stderr);
    }
    // Genuinely unknown verbs keep the usage path, not a hint.
    let r = run_cli(None, &["frobnicate"], None, false);
    assert_eq!(r.status, 2, "stderr={}", r.stderr);
    assert!(r.stderr.contains("unknown command"), "stderr={}", r.stderr);
}

#[test]
fn missing_token_fails_before_connect() {
    let r = run_cli(None, &["heartbeat"], None, true);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("AGENT_BUS_TOKEN"), "stderr={}", r.stderr);
    assert!(r.stdout.is_empty(), "stdout={}", r.stdout);
}

#[test]
fn cli_flag_secrets_are_rejected_in_favor_of_env() {
    let r = run_cli(None, &["--token", "sekret", "heartbeat"], None, false);
    assert_eq!(r.status, 2, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stderr.contains("AGENT_BUS_TOKEN"), "stderr={}", r.stderr);
    assert!(!r.stderr.contains("sekret"), "flag secret leaked: {}", r.stderr);
}

// ---------------------------------------------------------------------------
// RPC bounds: finite deadlines, bounded frames, strict req_id (wire::Client)
// ---------------------------------------------------------------------------

fn connect_tester(fx: &Fixture) -> Client {
    Client::connect(&fx.addr, "tester", "tok-test").expect("fixture hello must succeed")
}

#[test]
#[allow(clippy::assertions_on_constants, reason = "guards future edits to the documented bounds")]
fn rpc_bounds_are_documented_and_finite() {
    assert!(CLIENT_CONNECT_TIMEOUT > Duration::ZERO, "connect deadline must be finite positive");
    assert!(CLIENT_RPC_TIMEOUT > Duration::ZERO, "RPC deadline must be finite positive");
    assert!(CLIENT_CONNECT_TIMEOUT <= Duration::from_secs(30), "connect bound stays tight");
    assert!(CLIENT_RPC_TIMEOUT <= Duration::from_secs(30), "RPC bound stays tight");
    // History pages reach 4 MiB + overhead; the reply cap preserves them
    // while staying far below the 256 MiB broker inbound cap.
    assert!(CLIENT_RESP_LIMIT >= 4 * 1024 * 1024, "reply cap must fit legitimate pages");
    assert!(CLIENT_RESP_LIMIT <= 256 * 1024 * 1024, "reply cap must bound memory");
}

#[test]
fn rpc_success_echoes_matching_id() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true}))
    });
    let mut c = connect_tester(&fx);
    let resp = c.rpc(&json!({"op": "ping"})).expect("matching reply must succeed");
    assert_eq!(resp["ok"], json!(true));
    assert_eq!(resp["req_id"], json!(2), "hello used 1, this RPC must be 2: {resp}");
}

#[test]
fn rpc_auth_refusal_fails_without_leaking_token() {
    let fx = start_scripted(|_| ScriptResp::Json(json!({"error": "auth failed"})));
    let err = match Client::connect(&fx.addr, "tester", "tok-test") {
        Ok(_) => panic!("auth refusal must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    let msg = err.to_string();
    assert!(msg.contains("hello failed") || msg.contains("auth"), "{msg}");
    assert!(!msg.contains("tok-test"), "credential leaked: {msg}");
}

#[test]
fn rpc_missing_req_id_fails() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Raw("{\"ok\": true}\n".to_string())
    });
    let mut c = connect_tester(&fx);
    let err = c.rpc(&json!({"op": "ping"})).expect_err("missing req_id must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    let msg = err.to_string();
    assert!(msg.contains("req_id"), "{msg}");
    assert!(msg.contains('2'), "must name the expected id: {msg}");
    assert!(!msg.contains("tok-test"), "credential leaked: {msg}");
}

#[test]
fn rpc_mismatched_req_id_fails() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Raw("{\"ok\": true, \"req_id\": 999}\n".to_string())
    });
    let mut c = connect_tester(&fx);
    let err = c.rpc(&json!({"op": "ping"})).expect_err("mismatched req_id must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    let msg = err.to_string();
    assert!(msg.contains("mismatch"), "{msg}");
    assert!(msg.contains('2') && msg.contains("999"), "must name expected vs got: {msg}");
    assert!(!msg.contains("tok-test"), "credential leaked: {msg}");
}

#[test]
fn rpc_null_frame_error_stays_accepted() {
    // Preserved broker protocol: oversize/UTF-8 frame errors carry null.
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Raw("{\"req_id\": null, \"error\": \"frame exceeds byte limit\"}\n".to_string())
    });
    let mut c = connect_tester(&fx);
    let resp = c.rpc(&json!({"op": "ping"})).expect("null frame error must stay Ok");
    assert_eq!(resp["error"], json!("frame exceeds byte limit"));
}

#[test]
fn rpc_oversize_response_fails_with_bounded_diagnostic() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        let pad = "x".repeat(4096);
        ScriptResp::Raw(format!("{{\"ok\": true, \"req_id\": 2, \"pad\": \"{pad}\"}}\n"))
    });
    let mut c = connect_tester(&fx);
    c.set_response_limit(1024);
    let err = c.rpc(&json!({"op": "ping"})).expect_err("oversize reply must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    let msg = err.to_string();
    assert!(msg.contains("exceeds"), "{msg}");
    assert!(msg.contains("1024"), "must name the bound: {msg}");
    assert!(!msg.contains("xxxx"), "diagnostic must not echo the payload: {}", &msg[..msg.len().min(200)]);
    assert!(!msg.contains("tok-test"), "credential leaked: {msg}");
}

#[test]
fn rpc_silent_server_terminates_on_deadline() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Sleep(Duration::from_secs(5))
    });
    let mut c = connect_tester(&fx);
    c.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let start = Instant::now();
    let err = c.rpc(&json!({"op": "ping"})).expect_err("silent server must time out");
    let elapsed = start.elapsed();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(err.to_string().contains("timed out"), "{err}");
    assert!(elapsed < Duration::from_secs(4), "must not wait out the 5s server sleep: {elapsed:?}");
}

#[test]
fn rpc_partial_reply_terminates_on_deadline() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Partial("{\"ok\": true".to_string(), Duration::from_secs(5))
    });
    let mut c = connect_tester(&fx);
    c.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let start = Instant::now();
    let err = c.rpc(&json!({"op": "ping"})).expect_err("partial reply must time out");
    let elapsed = start.elapsed();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(elapsed < Duration::from_secs(4), "partial bytes must not hang: {elapsed:?}");
}

#[test]
fn rpc_slow_drip_terminates_on_absolute_deadline() {
    // One byte every 100ms stays under any per-read timeout; only the
    // absolute RPC deadline terminates it.
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Drip { chunk: vec![b'x'], count: 50, gap: Duration::from_millis(100) }
    });
    let mut c = connect_tester(&fx);
    c.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let start = Instant::now();
    let err = c.rpc(&json!({"op": "ping"})).expect_err("slow drip must time out");
    let elapsed = start.elapsed();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(elapsed < Duration::from_secs(4), "drip must not extend past the deadline: {elapsed:?}");
}

#[test]
fn rpc_timeout_never_retries_a_mutation() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Sleep(Duration::from_secs(5))
    });
    let mut c = connect_tester(&fx);
    c.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let err = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": {"n": 1}}))
        .expect_err("timed-out post must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    // Single attempt: the uncertain-status mutation is never resent.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(ops(&fx, "post").len(), 1, "timed-out mutation must not be retried");
}

#[test]
fn cli_surfaces_req_id_mismatch_without_token_leak() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Raw("{\"ok\": true, \"req_id\": 999}\n".to_string())
    });
    let r = run_cli(Some(&fx), &["heartbeat"], None, false);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.is_empty(), "stdout={}", r.stdout);
    assert!(r.stderr.contains("req_id"), "stderr={}", r.stderr);
    assert!(!r.stderr.contains("tok-test"), "token leaked: {}", r.stderr);
    assert!(!r.stdout.contains("tok-test"), "token leaked to stdout");
}

#[test]
fn cli_surfaces_missing_req_id_without_token_leak() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Raw("{\"ok\": true}\n".to_string())
    });
    let r = run_cli(Some(&fx), &["heartbeat"], None, false);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.is_empty(), "stdout={}", r.stdout);
    assert!(r.stderr.contains("req_id"), "stderr={}", r.stderr);
    assert!(!r.stderr.contains("tok-test"), "token leaked: {}", r.stderr);
}

// ---------------------------------------------------------------------------
// review closeout: evil-echo, bounded IDs, InvalidInput, slow-drain write
// ---------------------------------------------------------------------------

#[test]
fn rpc_connect_evil_echo_never_leaks_credential() {
    // Hostile broker echoes the supplied credential inside the hello reply;
    // the fixed connect diagnostic must not repeat any of it.
    const SYNTH: &str = "SYNTH-CRED-9f8e7d6c5b4a";
    let fx = start_scripted(|req| {
        if req.get("op").and_then(|v| v.as_str()) == Some("hello") {
            let tok = req.get("token").and_then(|v| v.as_str()).unwrap_or("?");
            return ScriptResp::Json(json!({
                "error": format!("auth failed for {tok} marker {SYNTH}"),
                "echo_token": tok,
                "marker": SYNTH,
            }));
        }
        ScriptResp::Json(json!({"ok": true}))
    });
    let err = match Client::connect(&fx.addr, "tester", "tok-test") {
        Ok(_) => panic!("evil-echo hello must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    let msg = err.to_string();
    assert!(msg.contains("hello failed"), "{msg}");
    assert!(!msg.contains("tok-test"), "client token leaked: {msg}");
    assert!(!msg.contains(SYNTH), "server echo leaked: {msg}");
    assert!(msg.len() < 200, "connect diagnostic must be bounded: {msg}");
}

#[test]
fn cli_connect_evil_echo_never_leaks_credential() {
    const SYNTH: &str = "SYNTH-CLI-CRED-7a1e04";
    let fx = start_scripted(|req| {
        if req.get("op").and_then(|v| v.as_str()) == Some("hello") {
            let tok = req.get("token").and_then(|v| v.as_str()).unwrap_or("?");
            return ScriptResp::Json(json!({
                "error": format!("denied {tok} {SYNTH}"),
                "echo": tok,
            }));
        }
        ScriptResp::Json(json!({"ok": true}))
    });
    let r = run_cli(Some(&fx), &["heartbeat"], None, false);
    assert_eq!(r.status, 1, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(r.stdout.is_empty(), "stdout={}", r.stdout);
    assert!(!r.stderr.contains("tok-test"), "token leaked: {}", r.stderr);
    assert!(!r.stderr.contains(SYNTH), "server echo leaked: {}", r.stderr);
}

#[test]
fn rpc_mismatched_req_id_long_string_is_bounded() {
    let hostile = format!("SYNTH-ID-{}-{}", "Q".repeat(64), "x".repeat(8000));
    let fx = start_scripted(move |req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Raw(format!(
            "{{\"ok\": true, \"req_id\": {}}}\n",
            serde_json::to_string(&hostile).unwrap()
        ))
    });
    let mut c = connect_tester(&fx);
    let err = c.rpc(&json!({"op": "ping"})).expect_err("long string id must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    let msg = err.to_string();
    assert!(msg.contains("mismatch"), "{msg}");
    assert!(msg.contains('2'), "must name expected id: {msg}");
    assert!(
        !msg.contains("SYNTH-ID"),
        "hostile id content leaked: {}",
        &msg[..msg.len().min(300)]
    );
    assert!(
        !msg.contains("xxxx"),
        "long id echoed: {}",
        &msg[..msg.len().min(300)]
    );
    assert!(!msg.contains("tok-test"), "credential leaked: {msg}");
    assert!(
        msg.len() < 300,
        "mismatch diagnostic must be bounded (got {}): {msg}",
        msg.len()
    );
}

#[test]
fn rpc_mismatched_req_id_maltyped_is_bounded() {
    let frames = [
        "{\"ok\": true, \"req_id\": {\"nested\": \"SYNTH-OBJ-SECRET\", \"big\": \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}}\n",
        "{\"ok\": true, \"req_id\": [1, 2, 3, \"SYNTH-ARR-SECRET\"]}\n",
        "{\"ok\": true, \"req_id\": true}\n",
        "{\"ok\": true, \"req_id\": 1.5}\n",
    ];
    for raw in frames {
        let frame = raw.to_string();
        let fx = start_scripted(move |req| {
            if let Some(r) = check_hello(req) {
                return r;
            }
            ScriptResp::Raw(frame.clone())
        });
        let mut c = connect_tester(&fx);
        let err = c
            .rpc(&json!({"op": "ping"}))
            .expect_err(format!("maltyped id must fail: {raw}").as_str());
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "frame {raw}: {err}");
        let msg = err.to_string();
        assert!(msg.contains("mismatch"), "frame {raw}: {msg}");
        assert!(msg.contains('2'), "must name expected id, frame {raw}: {msg}");
        assert!(!msg.contains("SYNTH"), "maltyped content leaked, frame {raw}: {msg}");
        assert!(!msg.contains("xxxx"), "maltyped payload echoed, frame {raw}: {msg}");
        assert!(!msg.contains("tok-test"), "credential leaked, frame {raw}: {msg}");
        assert!(
            msg.len() < 300,
            "mismatch diagnostic must be bounded, frame {raw} (got {}): {msg}",
            msg.len()
        );
    }
}

#[test]
fn rpc_non_object_input_returns_invalid_input() {
    let fx = start_scripted(|req| {
        if let Some(r) = check_hello(req) {
            return r;
        }
        ScriptResp::Json(json!({"ok": true}))
    });
    let mut c = connect_tester(&fx);
    for bad in [json!(null), json!(true), json!(42), json!("hi"), json!([1, 2])] {
        let err = c
            .rpc(&bad)
            .expect_err(format!("non-object must fail: {bad}").as_str());
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "input {bad}: {err}"
        );
        assert!(err.to_string().contains("object"), "input {bad}: {err}");
    }
    // Rejected inputs never touch the wire and must not consume req_id.
    assert_eq!(
        fx.received.lock().unwrap().len(),
        1,
        "bad inputs must not send frames"
    );
    let resp = c.rpc(&json!({"op": "ping"})).expect("client must stay usable");
    assert_eq!(
        resp["req_id"],
        json!(2),
        "rejected inputs must not consume req_id: {resp}"
    );
}

#[test]
fn rpc_slow_draining_peer_write_honors_overall_deadline() {
    // Peer reads hello normally, then drains the next request at ~1 KiB per
    // 50ms without replying. A 2 MiB request would take ~100s to drain; the
    // client must abort the write at its overall RPC deadline. Each partial
    // write succeeds quickly (no per-call timeout), so only the absolute
    // deadline terminates it. Single attempt: no resend on timeout.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else { return };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream.try_clone().unwrap();
        let mut slow = stream;
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let hello_id = serde_json::from_str::<Value>(&line)
            .ok()
            .and_then(|v| v.get("req_id").cloned())
            .unwrap_or(json!(1));
        let reply = json!({"ok": true, "agent": "tester", "req_id": hello_id});
        let mut bytes = serde_json::to_vec(&reply).unwrap();
        bytes.push(b'\n');
        if writer.write_all(&bytes).is_err() {
            return;
        }
        let _ = writer.flush();
        drop(reader);
        drop(writer);
        // Slow-drain phase: 1 KiB reads with 50ms pauses, never reply. Cap
        // the loop so a regressed (deadline-blind) client cannot hang the
        // harness; the client's elapsed assertion is the real check.
        use std::io::Read;
        let _ = slow.set_read_timeout(Some(Duration::from_millis(200)));
        let mut buf = [0u8; 1024];
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if Instant::now() >= end {
                break;
            }
            match slow.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => std::thread::sleep(Duration::from_millis(50)),
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    continue
                }
                Err(_) => break,
            }
        }
    });
    let mut c = Client::connect(&addr, "tester", "tok-test").expect("hello must succeed");
    c.set_rpc_timeout(Duration::from_millis(400)).unwrap();
    let big = "y".repeat(2 * 1024 * 1024);
    let start = Instant::now();
    let err = c
        .rpc(&json!({"op": "post", "topic": "t", "payload": big}))
        .expect_err("slow drain must time out");
    let elapsed = start.elapsed();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert!(err.to_string().contains("timed out"), "{err}");
    assert!(
        elapsed < Duration::from_secs(4),
        "slow-drain write must not extend past deadline: {elapsed:?}"
    );
}

#[test]
fn top_level_usage_advertises_last_alternative() {
    // Top-level help must name `--last N`: it is the tail
    // equivalent the `--tail` error and compat table point to.
    let output = std::process::Command::new(bin())
        .arg("--help")
        .env_clear()
        .output()
        .expect("help must run without a broker");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("--since-seq N") && text.contains("--last N"),
        "usage must advertise both show cursors: {text}"
    );
}

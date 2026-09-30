//! Independent review of native broker subscriptions (inbox703).
//!
//! Production source is read-only here; this file only adds wire-level
//! adversarial coverage over isolated ephemeral brokers: overlapping
//! subscriptions, bounded pending overflow accounting, disconnect
//! mid-replay, literal-fallback patterns, control-error survival,
//! replay-cursor-only `from_seq` semantics, unsubscribe robustness,
//! empty-topic and evicted-prefix cursors, CLI `sub` notes, same-agent
//! cross-connection visibility, and oversize close under backlog.
//! No Python, no production IO, `-j2` offline runs only.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use agent_bus::acl::TokenStore;
use agent_bus::wal::snapshot_path_for;
use agent_bus::wire::{Client, Server, StreamingConn};
use serde_json::{json, Value};

const T0: f64 = 1_790_000_000.0;

fn wal_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("agent-bus-subrev-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p.join("wal.log")
}

fn open_tokens() -> TokenStore {
    TokenStore::from_json_str(
        r#"{
            "tok-alice": {"agent": "alice", "publish": ["*"], "subscribe": ["*"]},
            "tok-bob": {"agent": "bob", "publish": ["board.build"], "subscribe": ["board.build"]},
            "tok-admin": {"agent": "*", "publish": ["*"], "subscribe": ["*"]}
        }"#,
    )
    .expect("fixture tokens valid")
}

fn start_with_handle(
    name: &str,
    tokens: TokenStore,
    frame_limit: Option<usize>,
) -> (String, PathBuf, Server) {
    let wal = wal_path(name);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(snapshot_path_for(&wal));
    let mut server = Server::new(wal.clone(), tokens).expect("fresh WAL starts clean");
    if let Some(limit) = frame_limit {
        server = server.with_frame_limit(limit);
    }
    let handle = server.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || server.serve(listener));
    (addr, wal, handle)
}

fn start_handle(name: &str) -> (String, PathBuf, Server) {
    start_with_handle(name, open_tokens(), None)
}

fn ok(v: &Value) -> bool {
    v.get("ok") == Some(&json!(true))
}

fn post(c: &mut Client, topic: &str, payload: Value) -> Value {
    c.rpc(&json!({"op": "post", "topic": topic, "payload": payload}))
        .unwrap()
}

fn cli_bin() -> String {
    env!("CARGO_BIN_EXE_agent-bus").to_string()
}

fn run_cli(addr: &str, agent: &str, token: &str, args: &[&str]) -> (i32, String, String) {
    let (host, port) = addr.rsplit_once(':').expect("addr has port");
    let out = Command::new(cli_bin())
        .args(args)
        .env("AGENT_BUS_AGENT", agent)
        .env("AGENT_BUS_TOKEN", token)
        .env_remove("AGENT_BUS_SOCK")
        .env("AGENT_BUS_HOST", host)
        .env("AGENT_BUS_PORT", port)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn agent-bus");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn stats_subs(c: &mut Client) -> usize {
    c.rpc(&json!({"op": "stats"})).unwrap()["stats"]["subs"]
        .as_u64()
        .unwrap_or(99) as usize
}

// Overlapping subscriptions on one connection each receive their own
// frame per post (no cross-sub dedup); removing one leaves the other
// live.
#[test]
fn overlap_same_conn_both_fire_and_partial_unsub_keeps_other() {
    let (addr, _wal, server) = start_handle("overlap");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id_exact, _, _) = s.subscribe("t", 0, 0).unwrap();
    let (id_glob, _, _) = s.subscribe("t*", 0, 0).unwrap();
    assert_ne!(id_exact, id_glob);
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&post(&mut p, "t", json!({"n": 1}))));
    let mut got = std::collections::HashSet::new();
    for _ in 0..2 {
        let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(fr["msg"]["seq"], json!(1));
        got.insert(fr["sub_id"].as_str().unwrap().to_string());
    }
    assert_eq!(
        got,
        std::collections::HashSet::from([id_exact.clone(), id_glob.clone()])
    );
    assert!(ok(&s.unsubscribe(&id_exact).unwrap()));
    assert!(ok(&post(&mut p, "t", json!({"n": 2}))));
    let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(fr["sub_id"], json!(id_glob));
    assert_eq!(fr["msg"]["seq"], json!(2));
    s.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let e = s.recv(Some(Duration::from_millis(300))).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e:?}");
    let _ = s.unsubscribe(&id_glob);
    server.set_fixed_now(None);
}

// Pending buffer overflow at the real registry: 2001 live posts to a
// pending subscription keep the newest 2000 and drop the oldest with
// per-sub and global accounting (deterministic; wire timing cannot
// force this branch on demand, so the registry path is pinned here
// while the wire flood below pins end-to-end accounting).
#[test]
fn pending_buffer_overflows_oldest_first_with_accounting() {
    use agent_bus::subs::{
        ConnOutbox, Matcher, PendingState, SubCounters, SubState, SubsRegistry, Subscription,
        SUBS_PENDING_MAX,
    };
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::AtomicU64;
    let mut reg = SubsRegistry::new();
    let counters = std::sync::Arc::new(SubCounters::new());
    reg.register_pending(Subscription {
        sub_id: "pending1".into(),
        pattern: "t".into(),
        matcher: Matcher::new("t"),
        agent: "alice".into(),
        conn_id: 7,
        outbox: std::sync::Arc::new(ConnOutbox::new(2000)),
        created: T0,
        counters: std::sync::Arc::clone(&counters),
        state: SubState::Pending(PendingState {
            snapshot: HashMap::from([("t".to_string(), 0)]),
            now: T0,
            from_seq: 0,
            tail: 0,
            pending: VecDeque::new(),
        }),
    });
    let deliveries = AtomicU64::new(0);
    let drops = AtomicU64::new(0);
    for n in 1..=(SUBS_PENDING_MAX + 1) {
        reg.deliver_live(
            "t",
            |id| json!({"event": "msg", "sub_id": id, "topic": "t", "msg": {"seq": n}}),
            &deliveries,
            &drops,
        );
    }
    let sub = reg.get("pending1").unwrap();
    let SubState::Pending(p) = &sub.state else {
        panic!("pending sub activated by fan-out");
    };
    assert_eq!(p.pending.len(), SUBS_PENDING_MAX);
    assert_eq!(p.pending[0]["msg"]["seq"], json!(2));
    assert_eq!(
        p.pending[SUBS_PENDING_MAX - 1]["msg"]["seq"],
        json!(SUBS_PENDING_MAX + 1)
    );
    assert_eq!(counters.dropped(), 1);
    assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(deliveries.load(std::sync::atomic::Ordering::SeqCst), 0);
    // Non-matching topics never touch the pending buffer.
    reg.deliver_live(
        "other",
        |id| json!({"event": "msg", "sub_id": id}),
        &deliveries,
        &drops,
    );
    assert_eq!(counters.dropped(), 1);
}

// Flood under a stalled writer: six publishers against one throttled
// subscriber outbox (cap 10). The writer delay is global, so one
// publisher is paced to the drain rate and can never force a backlog;
// six aggregate 6x the drain rate, so overflow is certain by rate
// math (not timing luck), and every live post is then accounted
// exactly once (received or dropped) with no duplicate seqs.
#[test]
fn flood_drops_accounted_exactly_under_stalled_writer() {
    let (addr, _wal, server) = start_handle("stalled-flood");
    server.set_fixed_now(Some(T0));
    server.set_subs_queue_max_for_test(10);
    server.set_writer_delay_for_test(1_000_000);
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    s.set_rpc_timeout(Duration::from_secs(30)).unwrap();
    let (sub_id, replayed, _) = s.subscribe("t", 0, 0).unwrap();
    assert_eq!(replayed, 0);
    // Six publishers x ten posts: aggregate arrival 6x the 1/s drain,
    // so ~50 frames must overflow the cap-10 outbox.
    let mut pubs = Vec::new();
    for k in 0..6 {
        let addr = addr.clone();
        pubs.push(std::thread::spawn(move || {
            let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
            c.set_rpc_timeout(Duration::from_secs(60)).unwrap();
            for n in 1..=10 {
                let r = c
                    .rpc(&json!({"op": "post", "topic": "t", "payload": {"pub": k, "n": n}}))
                    .unwrap();
                assert!(ok(&r), "publisher {k} blocked at {n}: {r}");
            }
        }));
    }
    for h in pubs {
        h.join().unwrap();
    }
    server.set_writer_delay_for_test(0);
    // Drain to quiescence: the identity must hold exactly; a timeout
    // means frames vanished without accounting (a real bug).
    let mut seqs: Vec<u64> = Vec::new();
    let mut queued = 1;
    let mut dropped = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        loop {
            match s.recv(Some(Duration::from_millis(200))) {
                Ok(fr) => seqs.push(fr["msg"]["seq"].as_u64().unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(e) => panic!("drain error: {e:?}"),
            }
        }
        let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
        let out = c.rpc(&json!({"op": "subs"})).unwrap();
        queued = out["subs"][0]["queued"].as_u64().unwrap();
        dropped = out["subs"][0]["dropped"].as_u64().unwrap();
        if queued == 0 && seqs.len() as u64 + dropped == 60 {
            break;
        }
    }
    assert_eq!(
        queued, 0,
        "outbox never drained (quit while frames in flight)"
    );
    assert!(dropped > 0, "no overflow under stalled writer");
    assert_eq!(seqs.len() as u64 + dropped, 60, "live accounting gap");
    let mut dedup = seqs.clone();
    dedup.sort_unstable();
    dedup.dedup();
    assert_eq!(dedup.len(), seqs.len(), "duplicate live seqs");
    let _ = s.unsubscribe(&sub_id);
    server.set_fixed_now(None);
}

// Disconnect mid-replay (reader blocked in reliable push) still
// releases the pending subscription: the writer fails, closes the
// outbox, and the reader cleans up instead of wedging.
#[test]
fn disconnect_mid_replay_releases_pending_sub() {
    use std::io::{BufRead, BufReader, Write};
    let (addr, _wal, server) = start_handle("replay-drop");
    server.set_fixed_now(Some(T0));
    server.set_subs_queue_max_for_test(2);
    server.set_writer_delay_for_test(50_000);
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=100 {
        assert!(ok(&post(&mut p, "t", json!({"n": n}))));
    }
    // Raw socket: hello, subscribe, read 3 replay frames (the reply
    // only follows the full replay, so 3 frames prove mid-replay),
    // then drop without reading further.
    let sock = std::net::TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut rd = BufReader::new(sock.try_clone().unwrap());
    let mut wr = sock;
    let mut seq = 0;
    let mut send = |v: Value| {
        seq += 1;
        let mut o = v;
        o["req_id"] = json!(seq);
        let mut b = serde_json::to_vec(&o).unwrap();
        b.push(b'\n');
        wr.write_all(&b).unwrap();
    };
    send(json!({"op": "hello", "agent": "alice", "token": "tok-alice"}));
    let mut line = String::new();
    rd.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"), "{line}");
    send(json!({"op": "subscribe", "pattern": "t"}));
    for _ in 0..3 {
        line.clear();
        rd.read_line(&mut line).unwrap();
        assert!(line.contains("\"event\":\"msg\""), "{line}");
    }
    drop(rd);
    drop(wr);
    // The pending sub must be released (writer fails, reader cleans).
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut subs = 1;
    for _ in 0..100 {
        subs = stats_subs(&mut c);
        if subs == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(subs, 0, "pending sub leaked after mid-replay drop");
    // Server healthy for new streams.
    server.set_writer_delay_for_test(0);
    server.set_subs_queue_max_for_test(2000);
    let mut s2 = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id2, rep2, _) = s2.subscribe("t", 0, 0).unwrap();
    assert_eq!(rep2, 100);
    let _ = s2.unsubscribe(&id2);
    server.set_fixed_now(None);
}

// Malformed-bracket patterns subscribe over the wire and match
// literally (fnmatch leniency); valid classes still match as classes.
// Bracket patterns never take the exact cursor shape.
#[test]
fn fallback_bracket_pattern_matches_literally_over_wire() {
    let (addr, _wal, server) = start_handle("fallback-wire");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id, rep, cursor) = s.subscribe("a[", 0, 0).unwrap();
    assert_eq!(rep, 0);
    assert!(
        cursor.is_none(),
        "bracket pattern must not take exact cursor"
    );
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&post(&mut p, "a[", json!({"n": 1}))));
    let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(fr["topic"], json!("a["));
    assert_eq!(fr["sub_id"], json!(id));
    assert!(ok(&post(&mut p, "ab", json!({"n": 2}))));
    s.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let e = s.recv(Some(Duration::from_millis(300))).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e:?}");
    let _ = s.unsubscribe(&id);
    // Valid class control: strict matching over the wire.
    s.set_rpc_timeout(Duration::from_secs(5)).unwrap();
    let (id2, _, cursor2) = s.subscribe("m[0-9]", 0, 0).unwrap();
    assert!(cursor2.is_none());
    assert!(ok(&post(&mut p, "m5", json!({"n": 3}))));
    let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(fr["topic"], json!("m5"));
    assert_eq!(fr["sub_id"], json!(id2));
    assert!(ok(&post(&mut p, "mx", json!({"n": 4}))));
    s.set_rpc_timeout(Duration::from_millis(300)).unwrap();
    let e = s.recv(Some(Duration::from_millis(300))).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e:?}");
    let _ = s.unsubscribe(&id2);
    server.set_fixed_now(None);
}

// Control errors are receipts, not connection deaths: after denied
// and malformed subscribes the same connection subscribes, posts,
// and stats normally.
#[test]
fn control_errors_keep_connection_usable() {
    let (addr, _wal, server) = start_handle("err-survive");
    server.set_fixed_now(Some(T0));
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let r = c
        .rpc(&json!({"op": "subscribe", "pattern": "t", "from_seq": "abc"}))
        .unwrap();
    assert!(r.get("error").is_some(), "{r}");
    assert!(r.get("req_id").is_some(), "{r}");
    let r = c.rpc(&json!({"op": "subscribe"})).unwrap();
    assert_eq!(r["error"], json!("subscribe denied: "), "{r}");
    // Same connection: valid subscribe on the empty topic parses (no
    // replay, control first), then stats/subs/post-to-unmatched-topic
    // all succeed (a post to `t` would interleave live before the
    // reply on a non-streaming reader, so matched live is proven by
    // the streaming tests instead).
    let r = c.rpc(&json!({"op": "subscribe", "pattern": "t"})).unwrap();
    assert!(ok(&r), "{r}");
    let out = c.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["subs"], json!(1), "{out}");
    assert!(ok(&post(&mut c, "other", json!({"n": 1}))));
    let out = c.rpc(&json!({"op": "subs"})).unwrap();
    assert_eq!(out["subs"].as_array().unwrap().len(), 1, "{out}");
    server.set_fixed_now(None);
}

// `from_seq` shapes replay only (matching Python `deliver`, which has
// no live filter): subscribing past the head replays nothing, but new
// posts still flow live.
#[test]
fn from_seq_beyond_head_filters_replay_only_live_flows() {
    let (addr, _wal, server) = start_handle("fromseq-max");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=3 {
        assert!(ok(&post(&mut p, "t", json!({"n": n}))));
    }
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id, rep, cur) = s.subscribe("t", u64::MAX, 0).unwrap();
    assert_eq!(rep, 0);
    assert_eq!(cur.expect("exact cursor")["topic_seq"], json!(3));
    assert!(ok(&post(&mut p, "t", json!({"n": 4}))));
    let fr = s.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(fr["msg"]["seq"], json!(4));
    assert_eq!(fr["sub_id"], json!(id));
    let _ = s.unsubscribe(&id);
    server.set_fixed_now(None);
}

// Unsubscribe tolerates missing and non-string ids (idempotent ok)
// and never disturbs the surviving subscription.
#[test]
fn unsubscribe_tolerates_missing_and_nonstr_id() {
    let (addr, _wal, server) = start_handle("unsub-robust");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id, _, _) = s.subscribe("t", 0, 0).unwrap();
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&c.rpc(&json!({"op": "unsubscribe"})).unwrap()));
    assert!(ok(&c
        .rpc(&json!({"op": "unsubscribe", "sub_id": 123}))
        .unwrap()));
    assert!(ok(&c
        .rpc(&json!({"op": "unsubscribe", "sub_id": Value::Null}))
        .unwrap()));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&post(&mut p, "t", json!({"n": 1}))));
    assert_eq!(
        s.recv(Some(Duration::from_secs(5))).unwrap()["msg"]["seq"],
        json!(1)
    );
    assert!(ok(&s.unsubscribe(&id).unwrap()));
    assert!(ok(&s.unsubscribe(&id).unwrap()));
    server.set_fixed_now(None);
}

// Empty-topic exact cursor: zero head, oldest 1, retained 0,
// untruncated (Python cursor shape parity).
#[test]
fn empty_topic_exact_cursor_shape() {
    let (addr, _wal, server) = start_handle("empty-cursor");
    server.set_fixed_now(Some(T0));
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (id, rep, cur) = s.subscribe("nope", 0, 0).unwrap();
    assert_eq!(rep, 0);
    let cur = cur.expect("exact cursor");
    assert_eq!(cur["topic"], json!("nope"));
    assert_eq!(cur["topic_seq"], json!(0));
    assert_eq!(cur["oldest_seq"], json!(1));
    assert_eq!(cur["retained"], json!(0));
    assert_eq!(cur["truncated"], json!(false));
    let _ = s.unsubscribe(&id);
    server.set_fixed_now(None);
}

// from_seq into the evicted prefix: replay starts at the retained
// floor (oldest) while the cursor exposes the gap for detection.
#[test]
fn from_seq_into_evicted_prefix_shows_gap_evidence() {
    let (addr, _wal, server) = start_handle("evict-gap");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=1005 {
        assert!(ok(&post(&mut p, "t", json!({"n": n}))));
    }
    let mut s = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    s.set_rpc_timeout(Duration::from_secs(30)).unwrap();
    let (id, rep, cur) = s.subscribe("t", 3, 0).unwrap();
    assert_eq!(rep, 1000);
    let cur = cur.expect("exact cursor");
    assert_eq!(cur["topic_seq"], json!(1005));
    assert_eq!(cur["oldest_seq"], json!(6));
    assert_eq!(cur["retained"], json!(1000));
    let f1 = s.recv(Some(Duration::from_secs(10))).unwrap();
    assert_eq!(f1["msg"]["seq"], json!(6));
    let _ = s.unsubscribe(&id);
    server.set_fixed_now(None);
}

// CLI `sub` notes: --count capping oldest-first replay, and a pattern
// matching no topics. Both exit 0 and leak nothing.
#[test]
fn cli_sub_count_cap_note_and_no_match_note() {
    let (addr, _wal, server) = start_handle("cli-notes");
    server.set_fixed_now(Some(T0));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    for n in 1..=5 {
        assert!(ok(&post(&mut p, "t", json!({"n": n}))));
    }
    let (st, stdout, stderr) = run_cli(
        &addr,
        "alice",
        "tok-alice",
        &["sub", "t", "--count", "2", "--format", "json"],
    );
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "stdout={stdout}");
    assert_eq!(lines[0].contains("\"seq\":1"), true, "{}", lines[0]);
    assert_eq!(lines[1].contains("\"seq\":2"), true, "{}", lines[1]);
    assert!(
        stderr.contains("capped oldest-first replay (5 buffered)"),
        "stderr={stderr}"
    );
    let (st, stdout, stderr) = run_cli(
        &addr,
        "alice",
        "tok-alice",
        &[
            "sub",
            "nomatch-*",
            "--once",
            "--timeout",
            "1",
            "--format",
            "json",
        ],
    );
    assert_eq!(st, 0, "stdout={stdout} stderr={stderr}");
    assert_eq!(stdout.lines().count(), 0, "stdout={stdout}");
    assert!(
        stderr.contains("matches no existing topics"),
        "stderr={stderr}"
    );
    let out = p.rpc(&json!({"op": "stats"})).unwrap();
    assert_eq!(out["stats"]["subs"], json!(0), "CLI sub leaked: {out}");
    server.set_fixed_now(None);
}

// Same-agent cross-connection: `subs` shows both connections' rows
// (agent visibility), but unsubscribe stays per-connection.
#[test]
fn same_agent_cross_conn_sees_but_cannot_remove() {
    let (addr, _wal, server) = start_handle("xconn-agent");
    server.set_fixed_now(Some(T0));
    let mut a = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (ida, _, _) = a.subscribe("tA", 0, 0).unwrap();
    let mut b = StreamingConn::connect(&addr, "alice", "tok-alice").unwrap();
    let (idb, _, _) = b.subscribe("tB", 0, 0).unwrap();
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let out = c.rpc(&json!({"op": "subs"})).unwrap();
    let rows = out["subs"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{out}");
    let mut ids: Vec<&str> = rows.iter().map(|r| r["sub_id"].as_str().unwrap()).collect();
    ids.sort_unstable();
    let mut expect = vec![ida.as_str(), idb.as_str()];
    expect.sort_unstable();
    assert_eq!(ids, expect);
    assert!(rows.iter().all(|r| r["agent"] == json!("alice")), "{out}");
    // Cross-connection unsubscribe is ok but a no-op.
    assert!(ok(&a.unsubscribe(&idb).unwrap()));
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    assert!(ok(&post(&mut p, "tB", json!({"n": 1}))));
    assert_eq!(
        b.recv(Some(Duration::from_secs(5))).unwrap()["msg"]["seq"],
        json!(1)
    );
    assert!(ok(&post(&mut p, "tA", json!({"n": 2}))));
    // Seqs are per-topic: first post to tA is tA seq 1.
    let fr = a.recv(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(fr["topic"], json!("tA"));
    assert_eq!(fr["msg"]["seq"], json!(1));
    let _ = a.unsubscribe(&ida);
    let _ = b.unsubscribe(&idb);
    server.set_fixed_now(None);
}

// Oversize close under backlog: with a flooded outbox the terminal
// null-id error must arrive promptly (stale live discarded via
// retain_reliable, not drained first), the connection drops, and owned
// subs are released. Without the discard the error would trail ~2000
// throttled live frames.
#[test]
fn oversize_close_discards_live_and_releases_subs() {
    use std::io::{BufRead, BufReader, Write};
    let (addr, _wal, server) = start_with_handle("oversize", open_tokens(), Some(64 * 1024));
    server.set_fixed_now(Some(T0));
    // A small, measured queue gives a bounded backlog without relying
    // on OS socket-buffer capacity. Delay applies to every writer, so
    // concurrent publishers are needed to outrun the subscriber.
    server.set_subs_queue_max_for_test(64);
    server.set_writer_delay_for_test(100_000);
    let sock = std::net::TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut rd = BufReader::new(sock.try_clone().unwrap());
    let mut wr = sock;
    let mut seq = 0;
    let mut send = |v: Value| {
        seq += 1;
        let mut o = v;
        o["req_id"] = json!(seq);
        let mut b = serde_json::to_vec(&o).unwrap();
        b.push(b'\n');
        wr.write_all(&b).unwrap();
    };
    let mut line = String::new();
    send(json!({"op": "hello", "agent": "alice", "token": "tok-alice"}));
    rd.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"), "{line}");
    // Subscribe on the empty topic (no replay), then produce live
    // frames from six connections. One synchronous publisher is paced
    // by the same writer delay and did not create any queued backlog
    // in the original experiment, even after 2500 posts.
    send(json!({"op": "subscribe", "pattern": "t"}));
    line.clear();
    rd.read_line(&mut line).unwrap();
    assert!(line.contains("\"ok\":true"), "{line}");
    let mut publishers = Vec::new();
    for publisher in 0..6 {
        let addr = addr.clone();
        publishers.push(std::thread::spawn(move || {
            let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
            for n in 1..=24 {
                let r = post(&mut p, "t", json!({"publisher": publisher, "n": n}));
                assert!(ok(&r), "publisher {publisher} blocked at {n}: {r}");
            }
        }));
    }
    for publisher in publishers {
        publisher.join().unwrap();
    }
    assert_eq!(server.posts(), 144, "all bounded fixture posts committed");
    let mut p = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let measured = p.rpc(&json!({"op": "subs"})).unwrap();
    assert_eq!(measured["subs"].as_array().unwrap().len(), 1);
    let queued_before_close = measured["subs"][0]["queued"].as_u64().unwrap();
    assert!(
        queued_before_close >= 32,
        "oversize-close experiment did not establish its claimed backlog: {measured}"
    );
    assert!(queued_before_close <= 64, "queue exceeded configured capacity");
    assert!(
        measured["subs"][0]["dropped"].as_u64().unwrap() > 0,
        "experiment must have exercised overflow: {measured}"
    );
    eprintln!("oversize-close measured precondition: {measured}");
    // Oversize post on the flooded connection: the terminal error must
    // arrive promptly despite >=32 queued frames (>=3.2s to drain at
    // the configured 100ms/frame), then EOF. At most the frame already
    // taken by the writer may precede the terminal error after purge.
    let big = "x".repeat(1024 * 1024);
    let start = std::time::Instant::now();
    send(json!({"op": "post", "topic": "t", "payload": {"big": big}}));
    drop(big);
    let mut saw_error = false;
    loop {
        line.clear();
        match rd.read_line(&mut line) {
            Ok(0) => break, // EOF after drain.
            Ok(_) => {
                if line.contains("frame exceeds byte limit") {
                    saw_error = true;
                }
            }
            // RST on close with unread backlog is terminal like EOF
            // (buffered bytes, including the error, were already read).
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                break
            }
            Err(e) => panic!("read error waiting for terminal frame: {e:?}"),
        }
        if start.elapsed() > Duration::from_secs(12) {
            break;
        }
    }
    assert!(saw_error, "terminal oversize error never arrived");
    eprintln!("oversize-close terminal elapsed: {:?}", start.elapsed());
    assert!(
        start.elapsed() < Duration::from_millis(1500),
        "error delayed behind live backlog: {:?}",
        start.elapsed()
    );
    drop(rd);
    drop(wr);
    // Owned sub released; server healthy.
    server.set_writer_delay_for_test(0);
    let mut c = Client::connect(&addr, "alice", "tok-alice").unwrap();
    let mut subs = 1;
    for _ in 0..50 {
        subs = stats_subs(&mut c);
        if subs == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(subs, 0, "sub leaked after oversize close");
    server.set_fixed_now(None);
}
